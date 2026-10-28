//! SQLite persistence with an intentionally small, auditable surface.

mod economy_shop;
pub use economy_shop::{ShopOrder, ShopProduct, ShopProductInput};
mod growth_lifecycle;
mod welcome;
pub use growth_lifecycle::{GrowthDailyMetric, GrowthOverview, growth_source};
mod topgg_sync;
pub use topgg_sync::{TopggSyncDetail, TopggSyncStatus};

mod activity_feed;
pub use activity_feed::ActivityFeedRecord;

mod achievement_activity;
pub use achievement_activity::AchievementProgress;

use anyhow::{Context, Result, anyhow, bail};
use chrono::{DateTime, Duration, Utc};
use helper_contracts::{EntitlementSnapshot, SessionClaims, is_valid_workflow_reaction};
use rusqlite::{Connection, OptionalExtension, params};
use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};
use uuid::Uuid;

#[derive(Clone)]
pub struct Store {
    conn: Arc<Mutex<Connection>>,
    database_path: Option<std::path::PathBuf>,
}

#[derive(Debug, Clone, Copy, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StorageMetrics {
    /// Total bytes occupied by the active Helper runtime and its data. This
    /// is intentionally not the whole VPS volume.
    pub product_bytes: u64,
    pub database_bytes: u64,
    pub volume_used_bytes: Option<u64>,
    pub volume_available_bytes: Option<u64>,
    pub volume_total_bytes: Option<u64>,
}

fn helper_product_bytes(database_path: &Path) -> u64 {
    let total = [
        database_path.to_path_buf(),
        PathBuf::from(format!("{}-wal", database_path.display())),
        PathBuf::from(format!("{}-shm", database_path.display())),
    ]
    .into_iter()
    .filter_map(|path| std::fs::metadata(path).ok().map(|metadata| metadata.len()))
    .sum::<u64>();
    // The active release is the Helper's runtime footprint. Old releases and
    // backups are deliberately excluded. Deployments may override the root;
    // otherwise derive it from the running binary (current/bin/<binary>).
    total.saturating_add(path_bytes(&helper_runtime_root()))
}

fn helper_runtime_root() -> PathBuf {
    if let Some(root) = std::env::var_os("HELPER_PRODUCT_ROOT") {
        return PathBuf::from(root);
    }
    if let Ok(executable) = std::env::current_exe()
        && let Some(bin) = executable.parent()
        && let Some(root) = bin.parent()
    {
        return root.to_path_buf();
    }
    PathBuf::from("/home/vozen/vozen-helper-rust/current")
}

fn path_bytes(path: &Path) -> u64 {
    let Ok(metadata) = std::fs::symlink_metadata(path) else {
        return 0;
    };
    if metadata.file_type().is_symlink() {
        return std::fs::canonicalize(path)
            .ok()
            .map(|target| path_bytes(&target))
            .unwrap_or(0);
    }
    if metadata.is_dir() {
        return std::fs::read_dir(path)
            .ok()
            .into_iter()
            .flatten()
            .filter_map(Result::ok)
            .map(|entry| path_bytes(&entry.path()))
            .sum();
    }
    metadata.len()
}

/// Durable scheduler row kept as a tuple to preserve the runtime's small
/// dispatch surface. The fields are `(id, guild_id, action_type, target_id,
/// payload)`.
pub type ScheduledAction = (i64, String, String, String, String);

#[derive(Debug, Clone, serde::Serialize)]
pub struct CaseRecord {
    pub id: i64,
    pub guild_id: String,
    pub kind: String,
    pub target_id: String,
    pub moderator_id: String,
    pub reason: String,
    pub duration_ms: Option<i64>,
    pub created_at: i64,
}

/// Structured evidence for a sensitive operation. The record is append-only
/// during normal operation and binds the actor, tenant, reason and outcome to
/// one correlation id so support can trace a moderation action end to end.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AuditEventRecord {
    pub id: i64,
    pub correlation_id: String,
    pub guild_id: String,
    pub actor_id: String,
    pub action: String,
    pub reason: String,
    pub before_json: String,
    pub after_json: String,
    pub outcome: String,
    pub created_at: i64,
}

/// Privacy-first activity entry.  Message content is never required here;
/// callers can store bounded metadata such as an id, channel and whether the
/// payload was available in the gateway event.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ActivityLogRecord {
    pub id: i64,
    pub guild_id: String,
    pub kind: String,
    pub user_id: String,
    pub user_tag: Option<String>,
    pub actor_id: Option<String>,
    pub detail: String,
    pub created_at: i64,
}

/// Last observed usage for a guild invite. Discord does not include the
/// invite that caused a member join in the gateway event, so the Helper keeps
/// only this bounded, non-secret counter snapshot and derives attribution from
/// a positive delta on the next join.
#[derive(Debug, Clone, serde::Serialize)]
pub struct InviteSnapshot {
    pub guild_id: String,
    pub code: String,
    pub uses: i64,
    pub inviter_id: Option<String>,
    pub updated_at: i64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct FeatureSettingRecord {
    pub guild_id: String,
    pub key: String,
    pub enabled: bool,
    pub config_json: String,
    pub revision: u64,
    pub updated_at: i64,
    pub updated_by: String,
}

/// Immutable snapshot of a Studio template. Revisions are guild-scoped and
/// append-only so the panel can show history and restore a previous version
/// without overwriting the audit trail.
#[derive(Debug, Clone, serde::Serialize)]
pub struct StudioTemplateRevisionRecord {
    pub guild_id: String,
    pub template_id: String,
    pub revision: u64,
    pub template_json: String,
    pub created_at: i64,
    pub created_by: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct YouTubeSubscriptionRecord {
    pub id: i64,
    pub guild_id: String,
    pub source_channel_id: String,
    pub target_channel_id: String,
    pub message_template: String,
    pub mention: String,
    pub enabled: bool,
    pub interval_seconds: i64,
    pub last_video_id: Option<String>,
    pub next_poll_at: i64,
    pub failure_count: i64,
    pub last_error: Option<String>,
    pub created_by: String,
    pub created_at: i64,
    pub updated_at: i64,
}

/// Subscription projection written together with a feature revision. Keeping
/// this input separate from the persisted record prevents callers from
/// mutating polling state while publishing configuration.
#[derive(Debug, Clone)]
pub struct YouTubeSubscriptionWrite {
    pub source_channel_id: String,
    pub target_channel_id: String,
    pub message_template: String,
    pub mention: String,
    pub enabled: bool,
    pub interval_seconds: i64,
    pub created_by: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct RssSubscriptionRecord {
    pub id: i64,
    pub guild_id: String,
    pub feed_url: String,
    pub target_channel_id: String,
    pub message_template: String,
    pub mention: String,
    pub enabled: bool,
    pub interval_seconds: i64,
    pub last_item_id: Option<String>,
    pub next_poll_at: i64,
    pub failure_count: i64,
    pub last_error: Option<String>,
    pub created_by: String,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone)]
pub struct RssSubscriptionWrite {
    pub feed_url: String,
    pub target_channel_id: String,
    pub message_template: String,
    pub mention: String,
    pub enabled: bool,
    pub interval_seconds: i64,
    pub created_by: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct BlueskySubscriptionRecord {
    pub id: i64,
    pub guild_id: String,
    pub source_handle: String,
    pub target_channel_id: String,
    pub message_template: String,
    pub mention: String,
    pub enabled: bool,
    pub interval_seconds: i64,
    pub last_post_uri: Option<String>,
    pub next_poll_at: i64,
    pub failure_count: i64,
    pub last_error: Option<String>,
    pub created_by: String,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone)]
pub struct BlueskySubscriptionWrite {
    pub source_handle: String,
    pub target_channel_id: String,
    pub message_template: String,
    pub mention: String,
    pub enabled: bool,
    pub interval_seconds: i64,
    pub created_by: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct RedditSubscriptionRecord {
    pub id: i64,
    pub guild_id: String,
    pub source_subreddit: String,
    pub target_channel_id: String,
    pub message_template: String,
    pub mention: String,
    pub enabled: bool,
    pub interval_seconds: i64,
    pub last_post_id: Option<String>,
    pub next_poll_at: i64,
    pub failure_count: i64,
    pub last_error: Option<String>,
    pub created_by: String,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone)]
pub struct RedditSubscriptionWrite {
    pub source_subreddit: String,
    pub target_channel_id: String,
    pub message_template: String,
    pub mention: String,
    pub enabled: bool,
    pub interval_seconds: i64,
    pub created_by: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct XSubscriptionRecord {
    pub id: i64,
    pub guild_id: String,
    pub source_handle: String,
    pub target_channel_id: String,
    pub message_template: String,
    pub mention: String,
    pub enabled: bool,
    pub interval_seconds: i64,
    pub last_post_id: Option<String>,
    pub next_poll_at: i64,
    pub failure_count: i64,
    pub last_error: Option<String>,
    pub created_by: String,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone)]
pub struct XSubscriptionWrite {
    pub source_handle: String,
    pub target_channel_id: String,
    pub message_template: String,
    pub mention: String,
    pub enabled: bool,
    pub interval_seconds: i64,
    pub created_by: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct TikTokSubscriptionRecord {
    pub id: i64,
    pub guild_id: String,
    pub source_label: String,
    pub target_channel_id: String,
    pub message_template: String,
    pub mention: String,
    pub enabled: bool,
    pub interval_seconds: i64,
    pub last_video_id: Option<String>,
    pub next_poll_at: i64,
    pub failure_count: i64,
    pub last_error: Option<String>,
    pub created_by: String,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone)]
pub struct TikTokSubscriptionWrite {
    pub source_label: String,
    pub target_channel_id: String,
    pub message_template: String,
    pub mention: String,
    pub enabled: bool,
    pub interval_seconds: i64,
    pub created_by: String,
}

#[derive(Debug, Clone)]
pub struct TikTokGrantRecord {
    pub guild_id: String,
    pub open_id: String,
    pub display_name: String,
    pub access_token_sealed: String,
    pub refresh_token_sealed: String,
    pub scopes: String,
    pub access_expires_at: i64,
    pub refresh_expires_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct InstagramSubscriptionRecord {
    pub id: i64,
    pub guild_id: String,
    pub source_label: String,
    pub target_channel_id: String,
    pub message_template: String,
    pub mention: String,
    pub enabled: bool,
    pub interval_seconds: i64,
    pub last_media_id: Option<String>,
    pub next_poll_at: i64,
    pub failure_count: i64,
    pub last_error: Option<String>,
    pub created_by: String,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone)]
pub struct InstagramSubscriptionWrite {
    pub source_label: String,
    pub target_channel_id: String,
    pub message_template: String,
    pub mention: String,
    pub enabled: bool,
    pub interval_seconds: i64,
    pub created_by: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct KickSubscriptionRecord {
    pub id: i64,
    pub guild_id: String,
    pub source_handle: String,
    pub target_channel_id: String,
    pub message_template: String,
    pub mention: String,
    pub enabled: bool,
    pub interval_seconds: i64,
    pub last_stream_id: Option<String>,
    pub next_poll_at: i64,
    pub failure_count: i64,
    pub last_error: Option<String>,
    pub created_by: String,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone)]
pub struct KickSubscriptionWrite {
    pub source_handle: String,
    pub target_channel_id: String,
    pub message_template: String,
    pub mention: String,
    pub enabled: bool,
    pub interval_seconds: i64,
    pub created_by: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct TwitchSubscriptionRecord {
    pub id: i64,
    pub guild_id: String,
    pub source_login: String,
    pub source_user_id: String,
    pub target_channel_id: String,
    pub message_template: String,
    pub mention: String,
    pub enabled: bool,
    pub pending_event_id: Option<String>,
    pub pending_stream_id: Option<String>,
    pub pending_started_at: Option<String>,
    pub last_event_id: Option<String>,
    pub next_poll_at: i64,
    pub failure_count: i64,
    pub last_error: Option<String>,
    pub created_by: String,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone)]
pub struct TwitchSubscriptionWrite {
    pub source_login: String,
    pub source_user_id: String,
    pub target_channel_id: String,
    pub message_template: String,
    pub mention: String,
    pub enabled: bool,
    pub created_by: String,
}

fn youtube_subscription_from_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<YouTubeSubscriptionRecord> {
    Ok(YouTubeSubscriptionRecord {
        id: row.get(0)?,
        guild_id: row.get(1)?,
        source_channel_id: row.get(2)?,
        target_channel_id: row.get(3)?,
        message_template: row.get(4)?,
        mention: row.get(5)?,
        enabled: row.get::<_, i64>(6)? != 0,
        interval_seconds: row.get(7)?,
        last_video_id: row.get(8)?,
        next_poll_at: row.get(9)?,
        failure_count: row.get(10)?,
        last_error: row.get(11)?,
        created_by: row.get(12)?,
        created_at: row.get(13)?,
        updated_at: row.get(14)?,
    })
}

fn rss_subscription_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RssSubscriptionRecord> {
    Ok(RssSubscriptionRecord {
        id: row.get(0)?,
        guild_id: row.get(1)?,
        feed_url: row.get(2)?,
        target_channel_id: row.get(3)?,
        message_template: row.get(4)?,
        mention: row.get(5)?,
        enabled: row.get::<_, i64>(6)? != 0,
        interval_seconds: row.get(7)?,
        last_item_id: row.get(8)?,
        next_poll_at: row.get(9)?,
        failure_count: row.get(10)?,
        last_error: row.get(11)?,
        created_by: row.get(12)?,
        created_at: row.get(13)?,
        updated_at: row.get(14)?,
    })
}

fn bluesky_subscription_from_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<BlueskySubscriptionRecord> {
    Ok(BlueskySubscriptionRecord {
        id: row.get(0)?,
        guild_id: row.get(1)?,
        source_handle: row.get(2)?,
        target_channel_id: row.get(3)?,
        message_template: row.get(4)?,
        mention: row.get(5)?,
        enabled: row.get::<_, i64>(6)? != 0,
        interval_seconds: row.get(7)?,
        last_post_uri: row.get(8)?,
        next_poll_at: row.get(9)?,
        failure_count: row.get(10)?,
        last_error: row.get(11)?,
        created_by: row.get(12)?,
        created_at: row.get(13)?,
        updated_at: row.get(14)?,
    })
}

fn reddit_subscription_from_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<RedditSubscriptionRecord> {
    Ok(RedditSubscriptionRecord {
        id: row.get(0)?,
        guild_id: row.get(1)?,
        source_subreddit: row.get(2)?,
        target_channel_id: row.get(3)?,
        message_template: row.get(4)?,
        mention: row.get(5)?,
        enabled: row.get::<_, i64>(6)? != 0,
        interval_seconds: row.get(7)?,
        last_post_id: row.get(8)?,
        next_poll_at: row.get(9)?,
        failure_count: row.get(10)?,
        last_error: row.get(11)?,
        created_by: row.get(12)?,
        created_at: row.get(13)?,
        updated_at: row.get(14)?,
    })
}

fn x_subscription_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<XSubscriptionRecord> {
    Ok(XSubscriptionRecord {
        id: row.get(0)?,
        guild_id: row.get(1)?,
        source_handle: row.get(2)?,
        target_channel_id: row.get(3)?,
        message_template: row.get(4)?,
        mention: row.get(5)?,
        enabled: row.get::<_, i64>(6)? != 0,
        interval_seconds: row.get(7)?,
        last_post_id: row.get(8)?,
        next_poll_at: row.get(9)?,
        failure_count: row.get(10)?,
        last_error: row.get(11)?,
        created_by: row.get(12)?,
        created_at: row.get(13)?,
        updated_at: row.get(14)?,
    })
}

fn tiktok_subscription_from_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<TikTokSubscriptionRecord> {
    Ok(TikTokSubscriptionRecord {
        id: row.get(0)?,
        guild_id: row.get(1)?,
        source_label: row.get(2)?,
        target_channel_id: row.get(3)?,
        message_template: row.get(4)?,
        mention: row.get(5)?,
        enabled: row.get::<_, i64>(6)? != 0,
        interval_seconds: row.get(7)?,
        last_video_id: row.get(8)?,
        next_poll_at: row.get(9)?,
        failure_count: row.get(10)?,
        last_error: row.get(11)?,
        created_by: row.get(12)?,
        created_at: row.get(13)?,
        updated_at: row.get(14)?,
    })
}

fn instagram_subscription_from_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<InstagramSubscriptionRecord> {
    Ok(InstagramSubscriptionRecord {
        id: row.get(0)?,
        guild_id: row.get(1)?,
        source_label: row.get(2)?,
        target_channel_id: row.get(3)?,
        message_template: row.get(4)?,
        mention: row.get(5)?,
        enabled: row.get::<_, i64>(6)? != 0,
        interval_seconds: row.get(7)?,
        last_media_id: row.get(8)?,
        next_poll_at: row.get(9)?,
        failure_count: row.get(10)?,
        last_error: row.get(11)?,
        created_by: row.get(12)?,
        created_at: row.get(13)?,
        updated_at: row.get(14)?,
    })
}

fn kick_subscription_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<KickSubscriptionRecord> {
    Ok(KickSubscriptionRecord {
        id: row.get(0)?,
        guild_id: row.get(1)?,
        source_handle: row.get(2)?,
        target_channel_id: row.get(3)?,
        message_template: row.get(4)?,
        mention: row.get(5)?,
        enabled: row.get::<_, i64>(6)? != 0,
        interval_seconds: row.get(7)?,
        last_stream_id: row.get(8)?,
        next_poll_at: row.get(9)?,
        failure_count: row.get(10)?,
        last_error: row.get(11)?,
        created_by: row.get(12)?,
        created_at: row.get(13)?,
        updated_at: row.get(14)?,
    })
}

fn twitch_subscription_from_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<TwitchSubscriptionRecord> {
    Ok(TwitchSubscriptionRecord {
        id: row.get(0)?,
        guild_id: row.get(1)?,
        source_login: row.get(2)?,
        source_user_id: row.get(3)?,
        target_channel_id: row.get(4)?,
        message_template: row.get(5)?,
        mention: row.get(6)?,
        enabled: row.get::<_, i64>(7)? != 0,
        pending_event_id: row.get(8)?,
        pending_stream_id: row.get(9)?,
        pending_started_at: row.get(10)?,
        last_event_id: row.get(11)?,
        next_poll_at: row.get(12)?,
        failure_count: row.get(13)?,
        last_error: row.get(14)?,
        created_by: row.get(15)?,
        created_at: row.get(16)?,
        updated_at: row.get(17)?,
    })
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct RetentionSummary {
    pub deleted: serde_json::Value,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct TagRecord {
    pub guild_id: String,
    pub name: String,
    pub content: String,
    pub author_id: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct BirthdayRecord {
    pub guild_id: String,
    pub user_id: String,
    pub month: u32,
    pub day: u32,
    pub last_announced_year: Option<i32>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct EconomyAccount {
    pub guild_id: String,
    pub user_id: String,
    pub balance: i64,
    pub last_daily_at: Option<i64>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct TempChannelRecord {
    pub guild_id: String,
    pub channel_id: String,
    pub owner_id: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct LevelRecord {
    pub guild_id: String,
    pub user_id: String,
    pub xp: i64,
}

/// A milestone that has been granted to a member.  The primary key makes
/// unlocks idempotent when Discord retries a message event or the gateway
/// reconnects.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AchievementRecord {
    pub guild_id: String,
    pub user_id: String,
    pub achievement_key: String,
    pub threshold: i64,
    pub unlocked_at: i64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct VoiceSessionRecord {
    pub guild_id: String,
    pub user_id: String,
    pub channel_id: String,
    pub started_at: i64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct AfkRecord {
    pub guild_id: String,
    pub user_id: String,
    pub reason: String,
    pub since: i64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct TicketRecord {
    pub guild_id: String,
    pub user_id: String,
    pub channel_id: String,
    pub status: String,
    pub claimed_by: Option<String>,
    pub category: String,
    pub priority: String,
    pub notes: String,
    pub csat: Option<i64>,
    pub created_at: i64,
    pub closed_at: Option<i64>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct EventRegistrationRecord {
    pub guild_id: String,
    pub event_id: String,
    pub user_id: String,
    pub status: String,
    pub created_at: i64,
    pub checked_in_at: Option<i64>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SessionGuildRecord {
    pub guild_id: String,
    pub name: String,
    pub permissions: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SuggestionRecord {
    pub id: i64,
    pub guild_id: String,
    pub author_id: String,
    pub content: String,
    pub message_id: Option<String>,
    pub channel_id: Option<String>,
    pub status: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct GiveawayRecord {
    pub id: i64,
    pub guild_id: String,
    pub channel_id: String,
    pub message_id: Option<String>,
    pub prize: String,
    pub winners: i64,
    pub end_at: i64,
    pub ended: bool,
    pub required_role_id: Option<String>,
    pub host_id: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct StarEntry {
    pub starboard_message_id: String,
    pub star_count: i64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct PollRecord {
    pub id: i64,
    pub guild_id: String,
    pub channel_id: String,
    pub message_id: Option<String>,
    pub question: String,
    pub options: Vec<String>,
    pub end_at: i64,
    pub closed: bool,
    pub created_at: i64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct WorkflowRecord {
    pub id: i64,
    pub guild_id: String,
    pub name: String,
    pub trigger: String,
    pub condition: String,
    pub action: String,
    pub payload: String,
    pub enabled: bool,
    pub created_at: i64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SkippedImportSetting {
    pub key: String,
    pub reason: String,
}
pub struct PreparedConfigImport {
    pub settings: Vec<(String, String)>,
    pub tags: Vec<(String, String, String)>,
    pub workflows: Vec<(String, String, String, String, bool)>,
    birthdays: Vec<(String, u32, u32)>,
}
pub struct ConfigImportLimits {
    pub tags: usize,
    pub workflows: usize,
    pub tag_length: usize,
    pub reply_length: usize,
}
impl Default for ConfigImportLimits {
    fn default() -> Self {
        Self {
            tags: 100,
            workflows: 100,
            tag_length: 2000,
            reply_length: 1000,
        }
    }
}
pub struct ConfigImportFeature {
    pub key: String,
    pub enabled: bool,
    pub config_json: String,
    pub expected_revision: u64,
    pub projections: Vec<(String, String)>,
    pub subscription: ImportSubscription,
}
pub enum ImportSubscription {
    None,
    YouTube(Option<YouTubeSubscriptionWrite>),
    Rss(Option<RssSubscriptionWrite>),
    Bluesky(Option<BlueskySubscriptionWrite>),
    TikTok(Option<TikTokSubscriptionWrite>),
    Twitch(Option<TwitchSubscriptionWrite>),
    Instagram(Option<InstagramSubscriptionWrite>),
    Kick(Option<KickSubscriptionWrite>),
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ConfigImportSummary {
    pub skipped_settings: Vec<SkippedImportSetting>,
    pub settings: usize,
    pub tags: usize,
    pub workflows: usize,
    pub birthdays: usize,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct QuarantineRecord {
    pub guild_id: String,
    pub user_id: String,
    pub role_ids: Vec<String>,
    pub reason: String,
    pub created_at: i64,
}

impl Store {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        if let Some(parent) = path.as_ref().parent() {
            std::fs::create_dir_all(parent)?;
        }
        let database_path = if path.as_ref() == Path::new(":memory:") {
            None
        } else {
            Some(path.as_ref().to_path_buf())
        };
        let conn = Connection::open(path).context("open helper sqlite")?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        let store = Self {
            conn: Arc::new(Mutex::new(conn)),
            database_path,
        };
        store.migrate()?;
        Ok(store)
    }

    /// Returns the SQLite footprint and, when the host exposes it, the free
    /// space of the volume containing the database. This is intentionally
    /// read-only and does not touch the database connection.
    pub fn storage_metrics(&self) -> StorageMetrics {
        let Some(path) = self.database_path.as_deref() else {
            return StorageMetrics {
                product_bytes: 0,
                database_bytes: 0,
                volume_used_bytes: None,
                volume_available_bytes: None,
                volume_total_bytes: None,
            };
        };

        let wal = path.with_file_name(format!(
            "{}-wal",
            path.file_name()
                .and_then(|name| name.to_str())
                .unwrap_or_default()
        ));
        let shm = path.with_file_name(format!(
            "{}-shm",
            path.file_name()
                .and_then(|name| name.to_str())
                .unwrap_or_default()
        ));
        let database_bytes = [path.to_path_buf(), wal, shm]
            .into_iter()
            .filter_map(|candidate| std::fs::metadata(candidate).ok())
            .map(|metadata| metadata.len())
            .sum();

        #[cfg(unix)]
        let volume = {
            let probe = path.parent().unwrap_or_else(|| Path::new("."));
            let probe = std::ffi::CString::new(probe.as_os_str().as_encoded_bytes()).ok();
            probe.and_then(|probe| {
                let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
                let result = unsafe { libc::statvfs(probe.as_ptr(), stat.as_mut_ptr()) };
                if result != 0 {
                    return None;
                }
                let stat = unsafe { stat.assume_init() };
                let block_size = stat.f_frsize.max(1);
                let total = stat.f_blocks.saturating_mul(block_size);
                let available = stat.f_bavail.saturating_mul(block_size);
                Some((total.saturating_sub(available), available, total))
            })
        };
        #[cfg(not(unix))]
        let volume: Option<(u64, u64, u64)> = None;

        let (volume_used_bytes, volume_available_bytes, volume_total_bytes) = volume
            .map(|(used, available, total)| (Some(used), Some(available), Some(total)))
            .unwrap_or((None, None, None));
        StorageMetrics {
            product_bytes: helper_product_bytes(path),
            database_bytes,
            volume_used_bytes,
            volume_available_bytes,
            volume_total_bytes,
        }
    }

    pub fn migrate(&self) -> Result<()> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        // Node-era databases can lack timestamps and/or the annual marker.
        // Add columns without rebuilding the table or resetting announcements.
        // A zero legacy timestamp means unknown, not the member's birth date.
        let birthdays_table_exists: i64 = conn.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='birthdays'",
            [],
            |row| row.get(0),
        )?;
        if birthdays_table_exists > 0 {
            let transaction = conn.unchecked_transaction()?;
            for (column, definition) in [
                ("last_announced_year", "INTEGER"),
                ("created_at", "INTEGER NOT NULL DEFAULT 0"),
                ("updated_at", "INTEGER NOT NULL DEFAULT 0"),
            ] {
                let exists: i64 = transaction.query_row(
                    "SELECT COUNT(*) FROM pragma_table_info('birthdays') WHERE name=?1",
                    [column],
                    |row| row.get(0),
                )?;
                if exists == 0 {
                    // Both SQL identifiers and types are the fixed list above.
                    transaction.execute(
                        &format!("ALTER TABLE birthdays ADD COLUMN {column} {definition}"),
                        [],
                    )?;
                }
            }
            transaction.commit()?;
        }
        conn.execute_batch("CREATE TABLE IF NOT EXISTS helper_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL); CREATE TABLE IF NOT EXISTS helper_sessions (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, guild_id TEXT NOT NULL, issued_at TEXT NOT NULL, expires_at TEXT NOT NULL, last_seen_at TEXT NOT NULL, revoked_at TEXT); CREATE TABLE IF NOT EXISTS helper_session_guilds (session_id TEXT NOT NULL, guild_id TEXT NOT NULL, name TEXT NOT NULL, permissions TEXT, PRIMARY KEY(session_id,guild_id)); CREATE TABLE IF NOT EXISTS helper_oauth_states (state_hash TEXT PRIMARY KEY, expires_at INTEGER NOT NULL, used_at INTEGER); CREATE TABLE IF NOT EXISTS helper_entitlements (subject_id TEXT PRIMARY KEY, payload TEXT NOT NULL, fetched_at TEXT NOT NULL); CREATE TABLE IF NOT EXISTS helper_usage (guild_id TEXT NOT NULL, user_id TEXT NOT NULL, quota_key TEXT NOT NULL, period TEXT NOT NULL, used INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(guild_id,user_id,quota_key,period)); CREATE TABLE IF NOT EXISTS cases (id INTEGER PRIMARY KEY AUTOINCREMENT, guild_id TEXT NOT NULL, type TEXT NOT NULL, target_id TEXT NOT NULL, moderator_id TEXT NOT NULL, reason TEXT NOT NULL DEFAULT '', duration_ms INTEGER, created_at INTEGER NOT NULL); CREATE INDEX IF NOT EXISTS idx_cases_guild_time ON cases(guild_id, created_at DESC); CREATE TABLE IF NOT EXISTS settings (guild_id TEXT NOT NULL, key TEXT NOT NULL, value TEXT NOT NULL, updated_at INTEGER NOT NULL, PRIMARY KEY(guild_id,key)); CREATE TABLE IF NOT EXISTS activity_log (id INTEGER PRIMARY KEY AUTOINCREMENT, guild_id TEXT NOT NULL, type TEXT NOT NULL, user_id TEXT NOT NULL, user_tag TEXT, actor_id TEXT, detail TEXT NOT NULL DEFAULT '{}', created_at INTEGER NOT NULL); CREATE INDEX IF NOT EXISTS idx_activity_guild_time ON activity_log(guild_id, created_at DESC); CREATE TABLE IF NOT EXISTS scheduled_actions (id INTEGER PRIMARY KEY AUTOINCREMENT, guild_id TEXT NOT NULL, type TEXT NOT NULL, target_id TEXT NOT NULL, execute_at INTEGER NOT NULL, payload TEXT NOT NULL DEFAULT '', case_id INTEGER); CREATE INDEX IF NOT EXISTS idx_scheduled_due ON scheduled_actions(execute_at); CREATE TABLE IF NOT EXISTS infractions (id INTEGER PRIMARY KEY AUTOINCREMENT, guild_id TEXT NOT NULL, target_id TEXT NOT NULL, weight INTEGER NOT NULL DEFAULT 1, source TEXT NOT NULL DEFAULT 'manual', created_at INTEGER NOT NULL); CREATE TABLE IF NOT EXISTS afk (guild_id TEXT NOT NULL, user_id TEXT NOT NULL, reason TEXT NOT NULL DEFAULT '', since INTEGER NOT NULL, PRIMARY KEY(guild_id,user_id)); CREATE TABLE IF NOT EXISTS tags (guild_id TEXT NOT NULL, name TEXT NOT NULL, content TEXT NOT NULL, author_id TEXT NOT NULL, created_at INTEGER NOT NULL, PRIMARY KEY(guild_id,name)); CREATE TABLE IF NOT EXISTS levels (guild_id TEXT NOT NULL, user_id TEXT NOT NULL, xp INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(guild_id,user_id)); CREATE TABLE IF NOT EXISTS achievements (guild_id TEXT NOT NULL, user_id TEXT NOT NULL, achievement_key TEXT NOT NULL, threshold INTEGER NOT NULL, unlocked_at INTEGER NOT NULL, PRIMARY KEY(guild_id,user_id,achievement_key)); CREATE INDEX IF NOT EXISTS idx_achievements_guild_user ON achievements(guild_id,user_id,unlocked_at); CREATE TABLE IF NOT EXISTS stats (guild_id TEXT NOT NULL, date TEXT NOT NULL, messages INTEGER NOT NULL DEFAULT 0, joins INTEGER NOT NULL DEFAULT 0, leaves INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(guild_id,date)); CREATE TABLE IF NOT EXISTS invite_snapshots (guild_id TEXT NOT NULL, code TEXT NOT NULL, uses INTEGER NOT NULL DEFAULT 0, inviter_id TEXT, updated_at INTEGER NOT NULL, PRIMARY KEY(guild_id,code)); CREATE TABLE IF NOT EXISTS invite_attributions (guild_id TEXT NOT NULL, user_id TEXT NOT NULL, code TEXT NOT NULL, inviter_id TEXT, joined_at INTEGER NOT NULL, PRIMARY KEY(guild_id,user_id)); CREATE INDEX IF NOT EXISTS idx_invite_attributions_guild ON invite_attributions(guild_id,joined_at DESC);")?;
        // XP awards are recorded separately from the materialized balance so
        // gateway retries and worker replays cannot inflate a member's XP.
        // The event key is scoped to a guild because Discord identifiers from
        // different sources may legitimately overlap in fixtures/imports.
        conn.execute_batch("CREATE TABLE IF NOT EXISTS xp_events (guild_id TEXT NOT NULL, user_id TEXT NOT NULL, event_key TEXT NOT NULL, source TEXT NOT NULL, amount INTEGER NOT NULL, created_at INTEGER NOT NULL, PRIMARY KEY(guild_id,event_key)); CREATE INDEX IF NOT EXISTS idx_xp_events_user_time ON xp_events(guild_id,user_id,created_at DESC);")?;
        conn.execute_batch("CREATE TABLE IF NOT EXISTS birthdays (guild_id TEXT NOT NULL, user_id TEXT NOT NULL, month INTEGER NOT NULL, day INTEGER NOT NULL, last_announced_year INTEGER, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, PRIMARY KEY(guild_id,user_id)); CREATE INDEX IF NOT EXISTS idx_birthdays_day ON birthdays(month,day,last_announced_year); CREATE TABLE IF NOT EXISTS economy_accounts (guild_id TEXT NOT NULL, user_id TEXT NOT NULL, balance INTEGER NOT NULL DEFAULT 0, last_daily_at INTEGER, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, PRIMARY KEY(guild_id,user_id)); CREATE INDEX IF NOT EXISTS idx_economy_guild_balance ON economy_accounts(guild_id,balance DESC); CREATE TABLE IF NOT EXISTS economy_ledger (id INTEGER PRIMARY KEY AUTOINCREMENT, guild_id TEXT NOT NULL, user_id TEXT NOT NULL, amount INTEGER NOT NULL, reason TEXT NOT NULL, idempotency_key TEXT NOT NULL UNIQUE, created_at INTEGER NOT NULL); CREATE INDEX IF NOT EXISTS idx_economy_ledger_account ON economy_ledger(guild_id,user_id,created_at DESC); CREATE TABLE IF NOT EXISTS temp_channels (guild_id TEXT NOT NULL, channel_id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, created_at INTEGER NOT NULL); CREATE INDEX IF NOT EXISTS idx_temp_channels_guild ON temp_channels(guild_id); CREATE TABLE IF NOT EXISTS voice_sessions (guild_id TEXT NOT NULL, user_id TEXT NOT NULL, channel_id TEXT NOT NULL, started_at INTEGER NOT NULL, PRIMARY KEY(guild_id,user_id)); CREATE INDEX IF NOT EXISTS idx_voice_sessions_guild ON voice_sessions(guild_id,started_at);")?;
        economy_shop::migrate(&conn)?;
        conn.execute_batch("CREATE TABLE IF NOT EXISTS economy_cooldowns (guild_id TEXT NOT NULL, user_id TEXT NOT NULL, kind TEXT NOT NULL, last_claim_at INTEGER NOT NULL, PRIMARY KEY(guild_id,user_id,kind)); CREATE INDEX IF NOT EXISTS idx_economy_cooldowns_kind ON economy_cooldowns(guild_id,kind,last_claim_at);")?;
        conn.execute_batch("CREATE TABLE IF NOT EXISTS provider_events (provider TEXT NOT NULL, event_id TEXT NOT NULL, payload TEXT NOT NULL, received_at INTEGER NOT NULL, PRIMARY KEY(provider,event_id));")?;
        // Acquisition data is deliberately separate from member/server content.
        // It is limited to the lifecycle needed for activation and retention,
        // and departed guild rows are erased by the regular retention sweep.
        conn.execute_batch("CREATE TABLE IF NOT EXISTS helper_growth_lifecycle (guild_id TEXT PRIMARY KEY, first_joined_at INTEGER NOT NULL, last_joined_at INTEGER NOT NULL, install_source TEXT NOT NULL DEFAULT 'unknown', setup_completed_at INTEGER, first_value_at INTEGER, last_activity_at INTEGER, departed_at INTEGER); CREATE INDEX IF NOT EXISTS idx_helper_growth_departed ON helper_growth_lifecycle(departed_at); CREATE TABLE IF NOT EXISTS helper_growth_activity_day (guild_id TEXT NOT NULL, day TEXT NOT NULL, PRIMARY KEY(guild_id,day)); CREATE TABLE IF NOT EXISTS helper_growth_retention_record (guild_id TEXT NOT NULL, window_days INTEGER NOT NULL CHECK(window_days IN (7,30)), PRIMARY KEY(guild_id,window_days)); CREATE TABLE IF NOT EXISTS helper_growth_daily_metric (day TEXT NOT NULL, source TEXT NOT NULL, event TEXT NOT NULL, value INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(day,source,event)); CREATE TABLE IF NOT EXISTS helper_topgg_sync_state (singleton INTEGER PRIMARY KEY CHECK(singleton=1), last_attempt_at INTEGER NOT NULL, last_success_at INTEGER, last_status INTEGER, last_server_count INTEGER, last_detail TEXT NOT NULL DEFAULT 'unknown', consecutive_failures INTEGER NOT NULL DEFAULT 0);")?;
        conn.execute_batch("CREATE TABLE IF NOT EXISTS helper_growth_activity_day_v2 (guild_id TEXT NOT NULL, day TEXT NOT NULL, PRIMARY KEY(guild_id,day));")?;
        conn.execute_batch("CREATE TABLE IF NOT EXISTS siwe_nonces (guild_id TEXT NOT NULL, user_id TEXT NOT NULL, nonce TEXT NOT NULL, expires_at INTEGER NOT NULL, used_at INTEGER, created_at INTEGER NOT NULL, PRIMARY KEY(guild_id,nonce)); CREATE INDEX IF NOT EXISTS idx_siwe_nonces_expiry ON siwe_nonces(expires_at,used_at);")?;
        let oauth_verifier_exists: i64 = conn.query_row(
            "SELECT COUNT(*) FROM pragma_table_info('helper_oauth_states') WHERE name='code_verifier'",
            [],
            |row| row.get(0),
        )?;
        if oauth_verifier_exists == 0 {
            conn.execute(
                "ALTER TABLE helper_oauth_states ADD COLUMN code_verifier TEXT",
                [],
            )?;
        }
        // Keep the ticket schema compatible with the existing Node Helper DB.
        // The owner column is named `opener_id` there; changing it to `user_id`
        // would make an in-place Rust cutover fail on the live database.
        conn.execute_batch("CREATE TABLE IF NOT EXISTS tickets (id INTEGER PRIMARY KEY AUTOINCREMENT, guild_id TEXT NOT NULL, channel_id TEXT NOT NULL, opener_id TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open', claimed_by TEXT, created_at INTEGER NOT NULL); CREATE INDEX IF NOT EXISTS idx_tickets_owner ON tickets(guild_id,opener_id,status); CREATE TABLE IF NOT EXISTS suggestions (id INTEGER PRIMARY KEY AUTOINCREMENT, guild_id TEXT NOT NULL, author_id TEXT NOT NULL, content TEXT NOT NULL, message_id TEXT, status TEXT NOT NULL DEFAULT 'pending', created_at INTEGER NOT NULL); CREATE TABLE IF NOT EXISTS suggestion_votes (suggestion_id INTEGER NOT NULL, user_id TEXT NOT NULL, vote INTEGER NOT NULL, PRIMARY KEY(suggestion_id,user_id)); CREATE TABLE IF NOT EXISTS giveaways (id INTEGER PRIMARY KEY AUTOINCREMENT, guild_id TEXT NOT NULL, channel_id TEXT NOT NULL, message_id TEXT, prize TEXT NOT NULL, winners INTEGER NOT NULL DEFAULT 1, end_at INTEGER NOT NULL, ended INTEGER NOT NULL DEFAULT 0, required_role_id TEXT, host_id TEXT NOT NULL, created_at INTEGER NOT NULL); CREATE TABLE IF NOT EXISTS giveaway_entries (giveaway_id INTEGER NOT NULL, user_id TEXT NOT NULL, PRIMARY KEY(giveaway_id,user_id)); CREATE TABLE IF NOT EXISTS polls (id INTEGER PRIMARY KEY AUTOINCREMENT, guild_id TEXT NOT NULL, channel_id TEXT NOT NULL, message_id TEXT, question TEXT NOT NULL, options TEXT NOT NULL, end_at INTEGER NOT NULL, closed INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL); CREATE TABLE IF NOT EXISTS poll_votes (poll_id INTEGER NOT NULL, user_id TEXT NOT NULL, choice INTEGER NOT NULL, PRIMARY KEY(poll_id,user_id)); CREATE TABLE IF NOT EXISTS workflows (id INTEGER PRIMARY KEY AUTOINCREMENT, guild_id TEXT NOT NULL, name TEXT NOT NULL, trigger TEXT NOT NULL, condition TEXT NOT NULL DEFAULT '', action TEXT NOT NULL, payload TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1, created_at INTEGER NOT NULL); CREATE TABLE IF NOT EXISTS workflow_runs (id INTEGER PRIMARY KEY AUTOINCREMENT, workflow_id INTEGER NOT NULL, guild_id TEXT NOT NULL, source_id TEXT NOT NULL, created_at INTEGER NOT NULL); CREATE INDEX IF NOT EXISTS idx_workflows_trigger ON workflows(guild_id,trigger,enabled); CREATE TABLE IF NOT EXISTS quarantine (guild_id TEXT NOT NULL, user_id TEXT NOT NULL, role_ids TEXT NOT NULL, reason TEXT NOT NULL DEFAULT '', created_at INTEGER NOT NULL, PRIMARY KEY(guild_id,user_id)); CREATE TABLE IF NOT EXISTS starboard (guild_id TEXT NOT NULL, original_message_id TEXT NOT NULL, starboard_message_id TEXT NOT NULL, star_count INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(guild_id,original_message_id));")?;
        conn.execute_batch("CREATE TABLE IF NOT EXISTS giveaway_results (giveaway_id INTEGER PRIMARY KEY, winners_json TEXT NOT NULL, announced INTEGER NOT NULL DEFAULT 0, claimed_at INTEGER);")?;
        conn.execute_batch("CREATE TABLE IF NOT EXISTS audit_events (id INTEGER PRIMARY KEY AUTOINCREMENT, correlation_id TEXT NOT NULL UNIQUE, guild_id TEXT NOT NULL, actor_id TEXT NOT NULL, action TEXT NOT NULL, reason TEXT NOT NULL DEFAULT '', before_json TEXT NOT NULL DEFAULT '{}', after_json TEXT NOT NULL DEFAULT '{}', outcome TEXT NOT NULL, created_at INTEGER NOT NULL); CREATE INDEX IF NOT EXISTS idx_audit_events_guild_time ON audit_events(guild_id, created_at DESC); CREATE TABLE IF NOT EXISTS feature_settings (guild_id TEXT NOT NULL, key TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 0, config_json TEXT NOT NULL DEFAULT '{}', revision INTEGER NOT NULL DEFAULT 0, updated_at INTEGER NOT NULL, updated_by TEXT NOT NULL DEFAULT '', PRIMARY KEY(guild_id,key)); CREATE TABLE IF NOT EXISTS feature_revisions (guild_id TEXT NOT NULL, key TEXT NOT NULL, revision INTEGER NOT NULL, enabled INTEGER NOT NULL, config_json TEXT NOT NULL, updated_at INTEGER NOT NULL, updated_by TEXT NOT NULL, PRIMARY KEY(guild_id,key,revision)); CREATE INDEX IF NOT EXISTS idx_feature_revisions_lookup ON feature_revisions(guild_id,key,revision DESC);")?;
        conn.execute_batch("CREATE TABLE IF NOT EXISTS studio_template_revisions (guild_id TEXT NOT NULL, template_id TEXT NOT NULL, revision INTEGER NOT NULL, template_json TEXT NOT NULL, created_at INTEGER NOT NULL, created_by TEXT NOT NULL, PRIMARY KEY(guild_id,template_id,revision)); CREATE INDEX IF NOT EXISTS idx_studio_template_revisions_lookup ON studio_template_revisions(guild_id,template_id,revision DESC);")?;
        // Member-add events can be delivered more than once. Keep a short
        // guild/user claim so welcome messages remain idempotent without
        // permanently suppressing a genuine re-join.
        conn.execute_batch("CREATE TABLE IF NOT EXISTS welcome_delivery_claims (guild_id TEXT NOT NULL, user_id TEXT NOT NULL, kind TEXT NOT NULL, claimed_at INTEGER NOT NULL, PRIMARY KEY(guild_id,user_id,kind)); CREATE INDEX IF NOT EXISTS idx_welcome_delivery_claims_time ON welcome_delivery_claims(guild_id,claimed_at);")?;
        let suggestion_channel_exists: i64 = conn.query_row(
            "SELECT COUNT(*) FROM pragma_table_info('suggestions') WHERE name='channel_id'",
            [],
            |row| row.get(0),
        )?;
        if suggestion_channel_exists == 0 {
            conn.execute("ALTER TABLE suggestions ADD COLUMN channel_id TEXT", [])?;
        }
        for (column, definition) in [
            ("category", "TEXT NOT NULL DEFAULT 'general'"),
            ("priority", "TEXT NOT NULL DEFAULT 'normal'"),
            ("notes", "TEXT NOT NULL DEFAULT ''"),
            ("csat", "INTEGER"),
            ("closed_at", "INTEGER"),
        ] {
            let exists: i64 = conn.query_row(
                "SELECT COUNT(*) FROM pragma_table_info('tickets') WHERE name=?1",
                [column],
                |row| row.get(0),
            )?;
            if exists == 0 {
                conn.execute(
                    &format!("ALTER TABLE tickets ADD COLUMN {column} {definition}"),
                    [],
                )?;
            }
        }
        conn.execute_batch("CREATE TABLE IF NOT EXISTS event_registrations (guild_id TEXT NOT NULL, event_id TEXT NOT NULL, user_id TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'registered', created_at INTEGER NOT NULL, checked_in_at INTEGER, PRIMARY KEY(guild_id,event_id,user_id)); CREATE INDEX IF NOT EXISTS idx_event_registrations_event ON event_registrations(guild_id,event_id,status);")?;
        conn.execute_batch("CREATE TABLE IF NOT EXISTS twitch_subscriptions (id INTEGER PRIMARY KEY AUTOINCREMENT, guild_id TEXT NOT NULL, source_login TEXT NOT NULL, source_user_id TEXT NOT NULL, target_channel_id TEXT NOT NULL, message_template TEXT NOT NULL DEFAULT '{broadcaster} is live!\\nhttps://twitch.tv/{login}', mention TEXT NOT NULL DEFAULT '', enabled INTEGER NOT NULL DEFAULT 1, pending_event_id TEXT, pending_stream_id TEXT, pending_started_at TEXT, last_event_id TEXT, next_poll_at INTEGER NOT NULL, failure_count INTEGER NOT NULL DEFAULT 0, last_error TEXT, created_by TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, UNIQUE(guild_id,source_user_id,target_channel_id)); CREATE INDEX IF NOT EXISTS idx_twitch_due ON twitch_subscriptions(enabled,next_poll_at); CREATE INDEX IF NOT EXISTS idx_twitch_user ON twitch_subscriptions(source_user_id,enabled); CREATE INDEX IF NOT EXISTS idx_twitch_guild ON twitch_subscriptions(guild_id,updated_at DESC);")?;
        let twitch_last_event_exists: i64 = conn.query_row(
            "SELECT COUNT(*) FROM pragma_table_info('twitch_subscriptions') WHERE name='last_event_id'",
            [],
            |row| row.get(0),
        )?;
        if twitch_last_event_exists == 0 {
            conn.execute(
                "ALTER TABLE twitch_subscriptions ADD COLUMN last_event_id TEXT",
                [],
            )?;
        }
        conn.execute_batch("CREATE TABLE IF NOT EXISTS youtube_subscriptions (id INTEGER PRIMARY KEY AUTOINCREMENT, guild_id TEXT NOT NULL, source_channel_id TEXT NOT NULL, target_channel_id TEXT NOT NULL, message_template TEXT NOT NULL DEFAULT 'New video from {channel}: **{title}**\\n{url}', mention TEXT NOT NULL DEFAULT '', enabled INTEGER NOT NULL DEFAULT 1, interval_seconds INTEGER NOT NULL DEFAULT 300, last_video_id TEXT, next_poll_at INTEGER NOT NULL, failure_count INTEGER NOT NULL DEFAULT 0, last_error TEXT, created_by TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, UNIQUE(guild_id,source_channel_id,target_channel_id)); CREATE INDEX IF NOT EXISTS idx_youtube_due ON youtube_subscriptions(enabled,next_poll_at); CREATE INDEX IF NOT EXISTS idx_youtube_guild ON youtube_subscriptions(guild_id,updated_at DESC);")?;
        conn.execute_batch("CREATE TABLE IF NOT EXISTS rss_subscriptions (id INTEGER PRIMARY KEY AUTOINCREMENT, guild_id TEXT NOT NULL, feed_url TEXT NOT NULL, target_channel_id TEXT NOT NULL, message_template TEXT NOT NULL DEFAULT 'New post from {feed}: **{title}**\\n{url}', mention TEXT NOT NULL DEFAULT '', enabled INTEGER NOT NULL DEFAULT 1, interval_seconds INTEGER NOT NULL DEFAULT 300, last_item_id TEXT, next_poll_at INTEGER NOT NULL, failure_count INTEGER NOT NULL DEFAULT 0, last_error TEXT, created_by TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, UNIQUE(guild_id,feed_url,target_channel_id)); CREATE INDEX IF NOT EXISTS idx_rss_due ON rss_subscriptions(enabled,next_poll_at); CREATE INDEX IF NOT EXISTS idx_rss_guild ON rss_subscriptions(guild_id,updated_at DESC);")?;
        conn.execute_batch("CREATE TABLE IF NOT EXISTS bluesky_subscriptions (id INTEGER PRIMARY KEY AUTOINCREMENT, guild_id TEXT NOT NULL, source_handle TEXT NOT NULL, target_channel_id TEXT NOT NULL, message_template TEXT NOT NULL DEFAULT 'New post from {handle}: **{text}**\\n{url}', mention TEXT NOT NULL DEFAULT '', enabled INTEGER NOT NULL DEFAULT 1, interval_seconds INTEGER NOT NULL DEFAULT 300, last_post_uri TEXT, next_poll_at INTEGER NOT NULL, failure_count INTEGER NOT NULL DEFAULT 0, last_error TEXT, created_by TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, UNIQUE(guild_id,source_handle,target_channel_id)); CREATE INDEX IF NOT EXISTS idx_bluesky_due ON bluesky_subscriptions(enabled,next_poll_at); CREATE INDEX IF NOT EXISTS idx_bluesky_guild ON bluesky_subscriptions(guild_id,updated_at DESC); CREATE TABLE IF NOT EXISTS reddit_subscriptions (id INTEGER PRIMARY KEY AUTOINCREMENT, guild_id TEXT NOT NULL, source_subreddit TEXT NOT NULL, target_channel_id TEXT NOT NULL, message_template TEXT NOT NULL DEFAULT 'New post in r/{subreddit}: **{title}**\\n{permalink}', mention TEXT NOT NULL DEFAULT '', enabled INTEGER NOT NULL DEFAULT 1, interval_seconds INTEGER NOT NULL DEFAULT 300, last_post_id TEXT, next_poll_at INTEGER NOT NULL, failure_count INTEGER NOT NULL DEFAULT 0, last_error TEXT, created_by TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, UNIQUE(guild_id,source_subreddit,target_channel_id)); CREATE INDEX IF NOT EXISTS idx_reddit_due ON reddit_subscriptions(enabled,next_poll_at); CREATE INDEX IF NOT EXISTS idx_reddit_guild ON reddit_subscriptions(guild_id,updated_at DESC); CREATE TABLE IF NOT EXISTS x_subscriptions (id INTEGER PRIMARY KEY AUTOINCREMENT, guild_id TEXT NOT NULL, source_handle TEXT NOT NULL, target_channel_id TEXT NOT NULL, message_template TEXT NOT NULL DEFAULT 'New post from @{handle}: **{text}**\\n{url}', mention TEXT NOT NULL DEFAULT '', enabled INTEGER NOT NULL DEFAULT 1, interval_seconds INTEGER NOT NULL DEFAULT 900, last_post_id TEXT, next_poll_at INTEGER NOT NULL, failure_count INTEGER NOT NULL DEFAULT 0, last_error TEXT, created_by TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, UNIQUE(guild_id,source_handle,target_channel_id)); CREATE INDEX IF NOT EXISTS idx_x_due ON x_subscriptions(enabled,next_poll_at); CREATE INDEX IF NOT EXISTS idx_x_guild ON x_subscriptions(guild_id,updated_at DESC); CREATE TABLE IF NOT EXISTS tiktok_subscriptions (id INTEGER PRIMARY KEY AUTOINCREMENT, guild_id TEXT NOT NULL, source_label TEXT NOT NULL, target_channel_id TEXT NOT NULL, message_template TEXT NOT NULL DEFAULT 'New TikTok video from {label}: **{title}**\\n{url}', mention TEXT NOT NULL DEFAULT '', enabled INTEGER NOT NULL DEFAULT 1, interval_seconds INTEGER NOT NULL DEFAULT 900, last_video_id TEXT, next_poll_at INTEGER NOT NULL, failure_count INTEGER NOT NULL DEFAULT 0, last_error TEXT, created_by TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, UNIQUE(guild_id,source_label,target_channel_id)); CREATE INDEX IF NOT EXISTS idx_tiktok_due ON tiktok_subscriptions(enabled,next_poll_at); CREATE INDEX IF NOT EXISTS idx_tiktok_guild ON tiktok_subscriptions(guild_id,updated_at DESC);")?;
        conn.execute_batch("CREATE TABLE IF NOT EXISTS tiktok_grants (guild_id TEXT PRIMARY KEY, open_id TEXT NOT NULL, display_name TEXT NOT NULL, access_token_sealed TEXT NOT NULL, refresh_token_sealed TEXT NOT NULL, scopes TEXT NOT NULL, access_expires_at INTEGER NOT NULL, refresh_expires_at INTEGER NOT NULL, updated_at INTEGER NOT NULL); CREATE INDEX IF NOT EXISTS idx_tiktok_grants_expiry ON tiktok_grants(access_expires_at);")?;
        conn.execute_batch("CREATE TABLE IF NOT EXISTS instagram_subscriptions (id INTEGER PRIMARY KEY AUTOINCREMENT, guild_id TEXT NOT NULL, source_label TEXT NOT NULL, target_channel_id TEXT NOT NULL, message_template TEXT NOT NULL DEFAULT 'New Instagram post from @{label}: **{caption}**\\n{url}', mention TEXT NOT NULL DEFAULT '', enabled INTEGER NOT NULL DEFAULT 1, interval_seconds INTEGER NOT NULL DEFAULT 900, last_media_id TEXT, next_poll_at INTEGER NOT NULL, failure_count INTEGER NOT NULL DEFAULT 0, last_error TEXT, created_by TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, UNIQUE(guild_id,source_label,target_channel_id)); CREATE INDEX IF NOT EXISTS idx_instagram_due ON instagram_subscriptions(enabled,next_poll_at); CREATE INDEX IF NOT EXISTS idx_instagram_guild ON instagram_subscriptions(guild_id,updated_at DESC); CREATE TABLE IF NOT EXISTS kick_subscriptions (id INTEGER PRIMARY KEY AUTOINCREMENT, guild_id TEXT NOT NULL, source_handle TEXT NOT NULL, target_channel_id TEXT NOT NULL, message_template TEXT NOT NULL DEFAULT '{handle} is live!\\n{url}', mention TEXT NOT NULL DEFAULT '', enabled INTEGER NOT NULL DEFAULT 1, interval_seconds INTEGER NOT NULL DEFAULT 300, last_stream_id TEXT, next_poll_at INTEGER NOT NULL, failure_count INTEGER NOT NULL DEFAULT 0, last_error TEXT, created_by TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, UNIQUE(guild_id,source_handle,target_channel_id)); CREATE INDEX IF NOT EXISTS idx_kick_due ON kick_subscriptions(enabled,next_poll_at); CREATE INDEX IF NOT EXISTS idx_kick_guild ON kick_subscriptions(guild_id,updated_at DESC);")?;
        let tx = conn.unchecked_transaction()?;
        growth_lifecycle::backfill_growth_retention(&tx)?;
        tx.commit()?;
        drop(conn);
        self.migrate_achievement_activity()?;
        Ok(())
    }

    pub fn save_session(&self, claims: &SessionClaims) -> Result<()> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.execute("INSERT OR REPLACE INTO helper_sessions (id,user_id,guild_id,issued_at,expires_at,last_seen_at,revoked_at) VALUES (?1,?2,?3,?4,?5,?6,NULL)", params![claims.session_id.to_string(), claims.user_id, claims.guild_id, claims.issued_at.to_rfc3339(), claims.expires_at.to_rfc3339(), claims.last_seen_at.to_rfc3339()])?;
        Ok(())
    }

    pub fn replace_session_guilds(
        &self,
        session_id: Uuid,
        guilds: &[(String, String, Option<String>)],
    ) -> Result<()> {
        let mut conn = self.conn.lock().expect("store mutex poisoned");
        let tx = conn.transaction()?;
        tx.execute(
            "DELETE FROM helper_session_guilds WHERE session_id=?1",
            [session_id.to_string()],
        )?;
        for (guild_id, name, permissions) in guilds {
            tx.execute(
                "INSERT INTO helper_session_guilds(session_id,guild_id,name,permissions) VALUES(?1,?2,?3,?4)",
                params![session_id.to_string(), guild_id, name, permissions],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn session_guilds(&self, session_id: Uuid) -> Result<Vec<SessionGuildRecord>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let mut stmt = conn.prepare(
            "SELECT guild_id,name,permissions FROM helper_session_guilds WHERE session_id=?1 ORDER BY name COLLATE NOCASE",
        )?;
        let rows = stmt.query_map([session_id.to_string()], |row| {
            Ok(SessionGuildRecord {
                guild_id: row.get(0)?,
                name: row.get(1)?,
                permissions: row.get(2)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn register_oauth_state(
        &self,
        state_hash: &str,
        expires_at: i64,
        code_verifier: &str,
    ) -> Result<()> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.execute(
            "DELETE FROM helper_oauth_states WHERE expires_at < ?1 OR used_at < ?1 - 3600",
            [Utc::now().timestamp()],
        )?;
        let pending: i64 = conn.query_row(
            "SELECT COUNT(*) FROM helper_oauth_states WHERE used_at IS NULL",
            [],
            |row| row.get(0),
        )?;
        if pending >= 4096 {
            bail!("oauth_pending_limit");
        }
        conn.execute(
            "INSERT OR REPLACE INTO helper_oauth_states(state_hash,expires_at,used_at,code_verifier) VALUES(?1,?2,NULL,?3)",
            params![state_hash, expires_at, code_verifier],
        )?;
        Ok(())
    }

    pub fn consume_oauth_state(&self, state_hash: &str, now: i64) -> Result<Option<String>> {
        let mut conn = self.conn.lock().expect("store mutex poisoned");
        let tx = conn.transaction()?;
        let verifier = tx
            .query_row(
                "SELECT code_verifier FROM helper_oauth_states WHERE state_hash=?1 AND used_at IS NULL AND expires_at>=?2",
                params![state_hash, now],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()?
            .flatten();
        let Some(verifier) = verifier else {
            tx.commit()?;
            return Ok(None);
        };
        let changed = tx.execute(
            "UPDATE helper_oauth_states SET used_at=?2 WHERE state_hash=?1 AND used_at IS NULL AND expires_at>=?2",
            params![state_hash, now],
        )?;
        tx.commit()?;
        if changed == 1 {
            Ok(Some(verifier))
        } else {
            Ok(None)
        }
    }

    pub fn issue_siwe_nonce(
        &self,
        guild_id: &str,
        user_id: &str,
        nonce: &str,
        expires_at: i64,
    ) -> Result<()> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let now = Utc::now().timestamp();
        conn.execute(
            "DELETE FROM siwe_nonces WHERE expires_at < ?1 OR used_at IS NOT NULL",
            [now],
        )?;
        conn.execute(
            "INSERT INTO siwe_nonces(guild_id,user_id,nonce,expires_at,used_at,created_at) VALUES(?1,?2,?3,?4,NULL,?5)",
            params![guild_id, user_id, nonce, expires_at, now],
        )?;
        Ok(())
    }

    pub fn consume_siwe_nonce(
        &self,
        guild_id: &str,
        user_id: &str,
        nonce: &str,
        now: i64,
    ) -> Result<bool> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let changed = conn.execute(
            "UPDATE siwe_nonces SET used_at=?4 WHERE guild_id=?1 AND user_id=?2 AND nonce=?3 AND used_at IS NULL AND expires_at>=?4",
            params![guild_id, user_id, nonce, now],
        )?;
        Ok(changed == 1)
    }

    pub fn load_session(&self, id: Uuid) -> Result<Option<SessionClaims>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let row = conn.query_row("SELECT user_id,guild_id,issued_at,expires_at,last_seen_at,revoked_at FROM helper_sessions WHERE id=?1", [id.to_string()], |r| {
            let revoked: Option<String> = r.get(5)?;
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, String>(3)?, r.get::<_, String>(4)?, revoked))
        }).optional()?;
        let Some((user_id, guild_id, issued, expires, last_seen, revoked)) = row else {
            return Ok(None);
        };
        if revoked.is_some() {
            return Ok(None);
        }
        Ok(Some(SessionClaims {
            session_id: id,
            user_id,
            guild_id,
            issued_at: parse_dt(&issued)?,
            expires_at: parse_dt(&expires)?,
            last_seen_at: parse_dt(&last_seen)?,
        }))
    }

    pub fn revoke_session(&self, id: Uuid) -> Result<()> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.execute(
            "UPDATE helper_sessions SET revoked_at=?2 WHERE id=?1",
            params![id.to_string(), Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    pub fn touch_session(&self, id: Uuid, now: DateTime<Utc>) -> Result<bool> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let changed = conn.execute(
            "UPDATE helper_sessions SET last_seen_at=?2 WHERE id=?1 AND revoked_at IS NULL",
            params![id.to_string(), now.to_rfc3339()],
        )?;
        Ok(changed == 1)
    }

    pub fn save_entitlement(&self, snapshot: &EntitlementSnapshot) -> Result<()> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.execute("INSERT OR REPLACE INTO helper_entitlements (subject_id,payload,fetched_at) VALUES (?1,?2,?3)", params![snapshot.subject_id, serde_json::to_string(snapshot)?, snapshot.fetched_at.to_rfc3339()])?;
        Ok(())
    }

    pub fn record_case(
        &self,
        guild_id: &str,
        kind: &str,
        target_id: &str,
        moderator_id: &str,
        reason: &str,
        duration_ms: Option<i64>,
    ) -> Result<i64> {
        let mut conn = self.conn.lock().expect("store mutex poisoned");
        let tx = conn.transaction()?;
        let created_at = Utc::now().timestamp_millis();
        tx.execute("INSERT INTO cases(guild_id,type,target_id,moderator_id,reason,duration_ms,created_at) VALUES(?1,?2,?3,?4,?5,?6,?7)", params![guild_id, kind, target_id, moderator_id, reason, duration_ms, created_at])?;
        let case_id = tx.last_insert_rowid();
        let correlation_id = Uuid::new_v4().to_string();
        let before_json = serde_json::json!({"targetId": target_id}).to_string();
        let after_json = serde_json::json!({"caseId": case_id, "targetId": target_id, "durationMs": duration_ms}).to_string();
        tx.execute(
            "INSERT INTO audit_events(correlation_id,guild_id,actor_id,action,reason,before_json,after_json,outcome,created_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![correlation_id, guild_id, moderator_id, kind, reason, before_json, after_json, "recorded", created_at],
        )?;
        tx.commit()?;
        Ok(case_id)
    }

    pub fn recent_audit_events(&self, guild_id: &str, limit: u32) -> Result<Vec<AuditEventRecord>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let mut stmt = conn.prepare("SELECT id,correlation_id,guild_id,actor_id,action,reason,before_json,after_json,outcome,created_at FROM audit_events WHERE guild_id=?1 ORDER BY id DESC LIMIT ?2")?;
        let rows = stmt.query_map(params![guild_id, i64::from(limit.min(200))], |row| {
            Ok(AuditEventRecord {
                id: row.get(0)?,
                correlation_id: row.get(1)?,
                guild_id: row.get(2)?,
                actor_id: row.get(3)?,
                action: row.get(4)?,
                reason: row.get(5)?,
                before_json: row.get(6)?,
                after_json: row.get(7)?,
                outcome: row.get(8)?,
                created_at: row.get(9)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Append metadata-only activity.  Details are bounded before entering
    /// SQLite so an unexpected gateway payload cannot grow the audit table
    /// without limit.
    pub fn record_activity(
        &self,
        guild_id: &str,
        kind: &str,
        user_id: &str,
        user_tag: Option<&str>,
        actor_id: Option<&str>,
        detail: &str,
    ) -> Result<i64> {
        let bounded_detail = detail.chars().take(2_000).collect::<String>();
        let bounded_kind = kind.chars().take(80).collect::<String>();
        let bounded_user = user_id.chars().take(64).collect::<String>();
        let bounded_tag = user_tag.map(|value| value.chars().take(128).collect::<String>());
        let bounded_actor = actor_id.map(|value| value.chars().take(64).collect::<String>());
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.execute(
            "INSERT INTO activity_log(guild_id,type,user_id,user_tag,actor_id,detail,created_at) VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![
                guild_id,
                bounded_kind,
                bounded_user,
                bounded_tag,
                bounded_actor,
                bounded_detail,
                Utc::now().timestamp_millis()
            ],
        )?;
        Ok(conn.last_insert_rowid())
    }

    /// Claims a welcome delivery for a member. Discord may retry gateway
    /// events, so the same kind is suppressed during a bounded cooldown. A
    /// later genuine re-join can still receive the message.
    pub fn claim_welcome_delivery(
        &self,
        guild_id: &str,
        user_id: &str,
        kind: &str,
        now: i64,
        cooldown_seconds: i64,
    ) -> Result<bool> {
        if guild_id.is_empty()
            || user_id.is_empty()
            || kind.is_empty()
            || kind.len() > 64
            || cooldown_seconds < 0
        {
            bail!("welcome delivery claim is invalid");
        }
        let conn = self.conn.lock().expect("store mutex poisoned");
        let tx = conn.unchecked_transaction()?;
        let changed = tx.execute(
            "INSERT INTO welcome_delivery_claims(guild_id,user_id,kind,claimed_at) VALUES(?1,?2,?3,?4) ON CONFLICT(guild_id,user_id,kind) DO UPDATE SET claimed_at=excluded.claimed_at WHERE excluded.claimed_at - welcome_delivery_claims.claimed_at >= ?5",
            params![guild_id, user_id, kind, now, cooldown_seconds],
        )?;
        tx.commit()?;
        Ok(changed == 1)
    }

    pub fn recent_activity(&self, guild_id: &str, limit: u32) -> Result<Vec<ActivityLogRecord>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let mut stmt = conn.prepare(
            "SELECT id,guild_id,type,user_id,user_tag,actor_id,detail,created_at FROM activity_log WHERE guild_id=?1 ORDER BY id DESC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![guild_id, i64::from(limit.min(200))], |row| {
            Ok(ActivityLogRecord {
                id: row.get(0)?,
                guild_id: row.get(1)?,
                kind: row.get(2)?,
                user_id: row.get(3)?,
                user_tag: row.get(4)?,
                actor_id: row.get(5)?,
                detail: row.get(6)?,
                created_at: row.get(7)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn recent_cases(&self, guild_id: &str, limit: u32) -> Result<Vec<CaseRecord>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let mut stmt = conn.prepare("SELECT id,guild_id,type,target_id,moderator_id,reason,duration_ms,created_at FROM cases WHERE guild_id=?1 ORDER BY id DESC LIMIT ?2")?;
        let rows = stmt.query_map(params![guild_id, i64::from(limit.min(200))], |row| {
            Ok(CaseRecord {
                id: row.get(0)?,
                guild_id: row.get(1)?,
                kind: row.get(2)?,
                target_id: row.get(3)?,
                moderator_id: row.get(4)?,
                reason: row.get(5)?,
                duration_ms: row.get(6)?,
                created_at: row.get(7)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn cases_for_target(
        &self,
        guild_id: &str,
        target_id: &str,
        limit: u32,
    ) -> Result<Vec<CaseRecord>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let mut stmt = conn.prepare("SELECT id,guild_id,type,target_id,moderator_id,reason,duration_ms,created_at FROM cases WHERE guild_id=?1 AND target_id=?2 ORDER BY id DESC LIMIT ?3")?;
        let rows = stmt.query_map(
            params![guild_id, target_id, i64::from(limit.min(200))],
            |row| {
                Ok(CaseRecord {
                    id: row.get(0)?,
                    guild_id: row.get(1)?,
                    kind: row.get(2)?,
                    target_id: row.get(3)?,
                    moderator_id: row.get(4)?,
                    reason: row.get(5)?,
                    duration_ms: row.get(6)?,
                    created_at: row.get(7)?,
                })
            },
        )?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn update_case_reason(&self, guild_id: &str, case_id: i64, reason: &str) -> Result<bool> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        Ok(conn.execute(
            "UPDATE cases SET reason=?3 WHERE id=?1 AND guild_id=?2",
            params![case_id, guild_id, reason],
        )? > 0)
    }

    pub fn consume_quota(
        &self,
        guild_id: &str,
        user_id: &str,
        key: &str,
        limit: u64,
        now: DateTime<Utc>,
    ) -> Result<bool> {
        if limit == 0 {
            return Ok(false);
        }
        let period = now.format("%Y-%m").to_string();
        let conn = self.conn.lock().expect("store mutex poisoned");
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        let mut statement = conn.prepare_cached(
            "INSERT INTO helper_usage(guild_id,user_id,quota_key,period,used) VALUES(?1,?2,?3,?4,1) ON CONFLICT(guild_id,user_id,quota_key,period) DO UPDATE SET used=used+1 WHERE used < ?5",
        )?;
        let changed = statement.execute(params![guild_id, user_id, key, period, limit])?;
        Ok(changed > 0)
    }

    pub fn due_scheduled_actions(&self, now_ms: i64, limit: u32) -> Result<Vec<ScheduledAction>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let mut stmt = conn.prepare("SELECT id,guild_id,type,target_id,payload FROM scheduled_actions WHERE execute_at<=?1 ORDER BY execute_at ASC LIMIT ?2")?;
        let rows = stmt.query_map(params![now_ms, i64::from(limit.min(100))], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn delete_scheduled_action(&self, id: i64) -> Result<()> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.execute("DELETE FROM scheduled_actions WHERE id=?1", [id])?;
        Ok(())
    }

    /// Remove all scheduled actions for one bounded feature object. This is
    /// used when an event is edited or cancelled so a stale reminder cannot
    /// fire after the object has changed.
    pub fn delete_scheduled_actions_for(
        &self,
        guild_id: &str,
        action_type: &str,
        target_id: &str,
    ) -> Result<usize> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        Ok(conn.execute(
            "DELETE FROM scheduled_actions WHERE guild_id=?1 AND type=?2 AND target_id=?3",
            params![guild_id, action_type, target_id],
        )?)
    }

    /// Records a provider event exactly once. The boolean is false for a
    /// duplicate webhook, making at-least-once providers idempotent.
    pub fn record_provider_event(
        &self,
        provider: &str,
        event_id: &str,
        payload: &str,
    ) -> Result<bool> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let changed = conn.execute(
            "INSERT OR IGNORE INTO provider_events(provider,event_id,payload,received_at) VALUES(?1,?2,?3,?4)",
            params![provider, event_id, payload, Utc::now().timestamp_millis()],
        )?;
        Ok(changed > 0)
    }

    pub fn load_entitlement(&self, subject_id: &str) -> Result<Option<EntitlementSnapshot>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let value: Option<String> = conn
            .query_row(
                "SELECT payload FROM helper_entitlements WHERE subject_id=?1",
                [subject_id],
                |r| r.get(0),
            )
            .optional()?;
        value
            .map(|v| serde_json::from_str(&v).context("decode entitlement snapshot"))
            .transpose()
    }

    pub fn set_afk(&self, guild_id: &str, user_id: &str, reason: &str) -> Result<()> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.execute(
            "INSERT INTO afk(guild_id,user_id,reason,since) VALUES(?1,?2,?3,?4) ON CONFLICT(guild_id,user_id) DO UPDATE SET reason=excluded.reason,since=excluded.since",
            params![guild_id, user_id, reason, Utc::now().timestamp_millis()],
        )?;
        Ok(())
    }

    pub fn get_afk(&self, guild_id: &str, user_id: &str) -> Result<Option<AfkRecord>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        Ok(conn
            .query_row(
                "SELECT guild_id,user_id,reason,since FROM afk WHERE guild_id=?1 AND user_id=?2",
                params![guild_id, user_id],
                |row| {
                    Ok(AfkRecord {
                        guild_id: row.get(0)?,
                        user_id: row.get(1)?,
                        reason: row.get(2)?,
                        since: row.get(3)?,
                    })
                },
            )
            .optional()?)
    }

    pub fn clear_afk(&self, guild_id: &str, user_id: &str) -> Result<bool> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        Ok(conn.execute(
            "DELETE FROM afk WHERE guild_id=?1 AND user_id=?2",
            params![guild_id, user_id],
        )? > 0)
    }

    /// Remove only voluntary member state. Moderation records remain intact so
    /// that the server's audit history is not silently rewritten when a member
    /// leaves or requests deletion of personal preferences.
    pub fn delete_member_voluntary_data(
        &self,
        guild_id: &str,
        user_id: &str,
    ) -> Result<serde_json::Value> {
        let mut conn = self.conn.lock().expect("store mutex poisoned");
        let tx = conn.transaction()?;
        let mut deleted = serde_json::Map::new();
        for (name, statement) in [
            (
                "suggestion_votes",
                "DELETE FROM suggestion_votes WHERE suggestion_id IN (SELECT id FROM suggestions WHERE guild_id=?2 AND author_id=?1) OR (user_id=?1 AND suggestion_id IN (SELECT id FROM suggestions WHERE guild_id=?2))",
            ),
            (
                "giveaway_entries",
                "DELETE FROM giveaway_entries WHERE user_id=?1 AND giveaway_id IN (SELECT id FROM giveaways WHERE guild_id=?2)",
            ),
            (
                "poll_votes",
                "DELETE FROM poll_votes WHERE user_id=?1 AND poll_id IN (SELECT id FROM polls WHERE guild_id=?2)",
            ),
            (
                "scheduled_reminders",
                "DELETE FROM scheduled_actions WHERE guild_id=?2 AND type='reminder' AND target_id=?1",
            ),
            (
                "event_registrations",
                "DELETE FROM event_registrations WHERE guild_id=?2 AND user_id=?1",
            ),
            ("afk", "DELETE FROM afk WHERE guild_id=?2 AND user_id=?1"),
            (
                "levels",
                "DELETE FROM levels WHERE guild_id=?2 AND user_id=?1",
            ),
            (
                "xp_events",
                "DELETE FROM xp_events WHERE guild_id=?2 AND user_id=?1",
            ),
            (
                "voice_sessions",
                "DELETE FROM voice_sessions WHERE guild_id=?2 AND user_id=?1",
            ),
            (
                "birthdays",
                "DELETE FROM birthdays WHERE guild_id=?2 AND user_id=?1",
            ),
            (
                "shop_notifications",
                "DELETE FROM scheduled_actions WHERE guild_id=?2 AND type='shop_notice' AND target_id IN (SELECT CAST(id AS TEXT) FROM economy_orders WHERE guild_id=?2 AND user_id=?1)",
            ),
            (
                "economy_orders",
                "DELETE FROM economy_orders WHERE guild_id=?2 AND user_id=?1",
            ),
            (
                "economy_accounts",
                "DELETE FROM economy_accounts WHERE guild_id=?2 AND user_id=?1",
            ),
            (
                "economy_ledger",
                "DELETE FROM economy_ledger WHERE guild_id=?2 AND user_id=?1",
            ),
            (
                "economy_cooldowns",
                "DELETE FROM economy_cooldowns WHERE guild_id=?2 AND user_id=?1",
            ),
            (
                "tags",
                "DELETE FROM tags WHERE guild_id=?2 AND author_id=?1",
            ),
            (
                "suggestions",
                "DELETE FROM suggestions WHERE guild_id=?2 AND author_id=?1",
            ),
        ] {
            let count = tx.execute(statement, params![user_id, guild_id])?;
            if count > 0 {
                deleted.insert(name.to_string(), serde_json::json!(count));
            }
        }
        tx.commit()?;
        Ok(serde_json::Value::Object(deleted))
    }

    pub fn upsert_tag(
        &self,
        guild_id: &str,
        name: &str,
        content: &str,
        author_id: &str,
    ) -> Result<()> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.execute(
            "INSERT INTO tags(guild_id,name,content,author_id,created_at) VALUES(?1,?2,?3,?4,?5) ON CONFLICT(guild_id,name) DO UPDATE SET content=excluded.content,author_id=excluded.author_id,created_at=excluded.created_at",
            params![guild_id, name, content, author_id, Utc::now().timestamp_millis()],
        )?;
        Ok(())
    }

    pub fn get_tag(&self, guild_id: &str, name: &str) -> Result<Option<TagRecord>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        Ok(conn
            .query_row(
                "SELECT guild_id,name,content,author_id,created_at FROM tags WHERE guild_id=?1 AND name=?2",
                params![guild_id, name],
                |row| {
                    Ok(TagRecord {
                        guild_id: row.get(0)?,
                        name: row.get(1)?,
                        content: row.get(2)?,
                        author_id: row.get(3)?,
                        created_at: row.get(4)?,
                    })
                },
            )
            .optional()?)
    }

    pub fn list_tags(&self, guild_id: &str, limit: u32) -> Result<Vec<String>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let mut stmt =
            conn.prepare("SELECT name FROM tags WHERE guild_id=?1 ORDER BY name LIMIT ?2")?;
        let rows = stmt.query_map(params![guild_id, i64::from(limit.min(100))], |row| {
            row.get(0)
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<String>>>()?)
    }

    pub fn list_tag_records(&self, guild_id: &str, limit: u32) -> Result<Vec<TagRecord>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let mut stmt = conn.prepare(
            "SELECT guild_id,name,content,author_id,created_at FROM tags WHERE guild_id=?1 ORDER BY name LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![guild_id, i64::from(limit.min(100))], |row| {
            Ok(TagRecord {
                guild_id: row.get(0)?,
                name: row.get(1)?,
                content: row.get(2)?,
                author_id: row.get(3)?,
                created_at: row.get(4)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn delete_tag(&self, guild_id: &str, name: &str) -> Result<bool> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        Ok(conn.execute(
            "DELETE FROM tags WHERE guild_id=?1 AND name=?2",
            params![guild_id, name],
        )? > 0)
    }

    pub fn set_birthday(&self, guild_id: &str, user_id: &str, month: u32, day: u32) -> Result<()> {
        if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
            bail!("invalid_birthday");
        }
        let now = Utc::now().timestamp_millis();
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.execute(
            "INSERT INTO birthdays(guild_id,user_id,month,day,created_at,updated_at) VALUES(?1,?2,?3,?4,?5,?5) ON CONFLICT(guild_id,user_id) DO UPDATE SET month=excluded.month,day=excluded.day,last_announced_year=NULL,updated_at=excluded.updated_at",
            params![guild_id, user_id, month, day, now],
        )?;
        Ok(())
    }

    pub fn remove_birthday(&self, guild_id: &str, user_id: &str) -> Result<bool> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        Ok(conn.execute(
            "DELETE FROM birthdays WHERE guild_id=?1 AND user_id=?2",
            params![guild_id, user_id],
        )? > 0)
    }

    pub fn due_birthdays(
        &self,
        month: u32,
        day: u32,
        year: i32,
        limit: u32,
    ) -> Result<Vec<BirthdayRecord>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let mut stmt = conn.prepare("SELECT guild_id,user_id,month,day,last_announced_year FROM birthdays WHERE month=?1 AND day=?2 AND (last_announced_year IS NULL OR last_announced_year<>?3) LIMIT ?4")?;
        let rows = stmt.query_map(
            params![month, day, year, i64::from(limit.min(500))],
            |row| {
                Ok(BirthdayRecord {
                    guild_id: row.get(0)?,
                    user_id: row.get(1)?,
                    month: row.get(2)?,
                    day: row.get(3)?,
                    last_announced_year: row.get(4)?,
                })
            },
        )?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Return birthdays for one guild only. Workers use this scoped query when
    /// each guild can choose its own announcement timezone.
    pub fn due_birthdays_for_guild(
        &self,
        guild_id: &str,
        month: u32,
        day: u32,
        year: i32,
        limit: u32,
    ) -> Result<Vec<BirthdayRecord>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let mut stmt = conn.prepare(
            "SELECT guild_id,user_id,month,day,last_announced_year FROM birthdays WHERE guild_id=?1 AND month=?2 AND day=?3 AND (last_announced_year IS NULL OR last_announced_year<>?4) LIMIT ?5",
        )?;
        let rows = stmt.query_map(
            params![guild_id, month, day, year, i64::from(limit.min(500))],
            |row| {
                Ok(BirthdayRecord {
                    guild_id: row.get(0)?,
                    user_id: row.get(1)?,
                    month: row.get(2)?,
                    day: row.get(3)?,
                    last_announced_year: row.get(4)?,
                })
            },
        )?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn mark_birthday_announced(
        &self,
        guild_id: &str,
        user_id: &str,
        year: i32,
    ) -> Result<bool> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        Ok(conn.execute("UPDATE birthdays SET last_announced_year=?3,updated_at=?4 WHERE guild_id=?1 AND user_id=?2 AND (last_announced_year IS NULL OR last_announced_year<>?3)", params![guild_id, user_id, year, Utc::now().timestamp_millis()])? > 0)
    }

    pub fn economy_account(&self, guild_id: &str, user_id: &str) -> Result<EconomyAccount> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let now = Utc::now().timestamp_millis();
        conn.execute(
            "INSERT OR IGNORE INTO economy_accounts(guild_id,user_id,balance,created_at,updated_at) VALUES(?1,?2,0,?3,?3)",
            params![guild_id, user_id, now],
        )?;
        Ok(conn.query_row(
            "SELECT guild_id,user_id,balance,last_daily_at FROM economy_accounts WHERE guild_id=?1 AND user_id=?2",
            params![guild_id, user_id],
            |row| {
                Ok(EconomyAccount {
                    guild_id: row.get(0)?,
                    user_id: row.get(1)?,
                    balance: row.get(2)?,
                    last_daily_at: row.get(3)?,
                })
            },
        )?)
    }

    /// Atomically claim a daily reward. `None` means the account has already
    /// claimed within the bounded 24-hour cooldown window.
    pub fn claim_daily(
        &self,
        guild_id: &str,
        user_id: &str,
        reward: i64,
    ) -> Result<Option<EconomyAccount>> {
        let reward = reward.clamp(1, 10_000);
        let now = Utc::now().timestamp_millis();
        let mut conn = self.conn.lock().expect("store mutex poisoned");
        let tx = conn.transaction()?;
        let existing: Option<(i64, Option<i64>)> = tx
            .query_row(
                "SELECT balance,last_daily_at FROM economy_accounts WHERE guild_id=?1 AND user_id=?2",
                params![guild_id, user_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let (balance, last_daily_at) = existing.unwrap_or((0, None));
        if last_daily_at.is_some_and(|last| now.saturating_sub(last) < 86_400_000) {
            return Ok(None);
        }
        let next_balance = balance.saturating_add(reward);
        let idempotency_key = format!(
            "daily:{}:{}:{}",
            guild_id,
            user_id,
            now.div_euclid(86_400_000)
        );
        let inserted = tx.execute(
            "INSERT OR IGNORE INTO economy_ledger(guild_id,user_id,amount,reason,idempotency_key,created_at) VALUES(?1,?2,?3,'daily',?4,?5)",
            params![guild_id, user_id, reward, idempotency_key, now],
        )?;
        if inserted == 0 {
            return Ok(None);
        }
        tx.execute(
            "INSERT INTO economy_accounts(guild_id,user_id,balance,last_daily_at,created_at,updated_at) VALUES(?1,?2,?3,?4,?5,?5) ON CONFLICT(guild_id,user_id) DO UPDATE SET balance=excluded.balance,last_daily_at=excluded.last_daily_at,updated_at=excluded.updated_at",
            params![guild_id, user_id, next_balance, now, now],
        )?;
        tx.commit()?;
        Ok(Some(EconomyAccount {
            guild_id: guild_id.into(),
            user_id: user_id.into(),
            balance: next_balance,
            last_daily_at: Some(now),
        }))
    }

    /// Atomically award a bounded non-daily economy reward. Cooldowns and the
    /// ledger share the same transaction so retries cannot mint credits twice.
    pub fn claim_economy_reward(
        &self,
        guild_id: &str,
        user_id: &str,
        kind: &str,
        amount: i64,
        cooldown_ms: i64,
    ) -> Result<Option<EconomyAccount>> {
        let kind = kind.trim();
        if kind.is_empty() || kind.len() > 32 {
            return Ok(None);
        }
        let amount = amount.clamp(1, 10_000);
        let cooldown_ms = cooldown_ms.clamp(1_000, 7 * 86_400_000);
        let now = Utc::now().timestamp_millis();
        let mut conn = self.conn.lock().expect("store mutex poisoned");
        let tx = conn.transaction()?;
        tx.execute(
            "INSERT OR IGNORE INTO economy_accounts(guild_id,user_id,balance,created_at,updated_at) VALUES(?1,?2,0,?3,?3)",
            params![guild_id, user_id, now],
        )?;
        let last: Option<i64> = tx
            .query_row(
                "SELECT last_claim_at FROM economy_cooldowns WHERE guild_id=?1 AND user_id=?2 AND kind=?3",
                params![guild_id, user_id, kind],
                |row| row.get(0),
            )
            .optional()?;
        if last.is_some_and(|value| now.saturating_sub(value) < cooldown_ms) {
            return Ok(None);
        }
        let idempotency_key = format!(
            "reward:{kind}:{guild_id}:{user_id}:{}",
            now.div_euclid(cooldown_ms)
        );
        if tx.execute(
            "INSERT OR IGNORE INTO economy_ledger(guild_id,user_id,amount,reason,idempotency_key,created_at) VALUES(?1,?2,?3,?4,?5,?6)",
            params![guild_id, user_id, amount, kind, idempotency_key, now],
        )? == 0 {
            return Ok(None);
        }
        let balance: i64 = tx.query_row(
            "SELECT balance FROM economy_accounts WHERE guild_id=?1 AND user_id=?2",
            params![guild_id, user_id],
            |row| row.get(0),
        )?;
        let next_balance = balance.saturating_add(amount);
        tx.execute(
            "UPDATE economy_accounts SET balance=?3,updated_at=?4 WHERE guild_id=?1 AND user_id=?2",
            params![guild_id, user_id, next_balance, now],
        )?;
        tx.execute(
            "INSERT INTO economy_cooldowns(guild_id,user_id,kind,last_claim_at) VALUES(?1,?2,?3,?4) ON CONFLICT(guild_id,user_id,kind) DO UPDATE SET last_claim_at=excluded.last_claim_at",
            params![guild_id, user_id, kind, now],
        )?;
        tx.commit()?;
        Ok(Some(EconomyAccount {
            guild_id: guild_id.into(),
            user_id: user_id.into(),
            balance: next_balance,
            last_daily_at: None,
        }))
    }

    pub fn economy_top(&self, guild_id: &str, limit: u32) -> Result<Vec<(String, i64)>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let mut stmt = conn.prepare(
            "SELECT user_id,balance FROM economy_accounts WHERE guild_id=?1 AND balance>0 ORDER BY balance DESC,user_id ASC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![guild_id, i64::from(limit.clamp(1, 25))], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn register_temp_channel(
        &self,
        guild_id: &str,
        channel_id: &str,
        owner_id: &str,
    ) -> Result<()> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.execute(
            "INSERT OR REPLACE INTO temp_channels(guild_id,channel_id,owner_id,created_at) VALUES(?1,?2,?3,?4)",
            params![guild_id, channel_id, owner_id, Utc::now().timestamp_millis()],
        )?;
        Ok(())
    }

    pub fn temp_channel(&self, channel_id: &str) -> Result<Option<TempChannelRecord>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        Ok(conn
            .query_row(
                "SELECT guild_id,channel_id,owner_id,created_at FROM temp_channels WHERE channel_id=?1",
                [channel_id],
                |row| {
                    Ok(TempChannelRecord {
                        guild_id: row.get(0)?,
                        channel_id: row.get(1)?,
                        owner_id: row.get(2)?,
                        created_at: row.get(3)?,
                    })
                },
            )
            .optional()?)
    }

    pub fn temp_channels(&self, guild_id: &str) -> Result<Vec<TempChannelRecord>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let mut statement = conn.prepare(
            "SELECT guild_id,channel_id,owner_id,created_at FROM temp_channels WHERE guild_id=?1",
        )?;
        let rows = statement.query_map([guild_id], |row| {
            Ok(TempChannelRecord {
                guild_id: row.get(0)?,
                channel_id: row.get(1)?,
                owner_id: row.get(2)?,
                created_at: row.get(3)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn active_temp_channels(&self, guild_id: &str) -> Result<i64> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.query_row(
            "SELECT COUNT(*) FROM temp_channels WHERE guild_id=?1",
            [guild_id],
            |row| row.get(0),
        )
        .map_err(Into::into)
    }

    pub fn remove_temp_channel(&self, channel_id: &str) -> Result<bool> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        Ok(conn.execute(
            "DELETE FROM temp_channels WHERE channel_id=?1",
            [channel_id],
        )? > 0)
    }

    pub fn get_setting(&self, guild_id: &str, key: &str) -> Result<Option<String>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        Ok(conn
            .query_row(
                "SELECT value FROM settings WHERE guild_id=?1 AND key=?2",
                params![guild_id, key],
                |row| row.get(0),
            )
            .optional()?)
    }

    pub fn get_feature_setting(
        &self,
        guild_id: &str,
        key: &str,
    ) -> Result<Option<FeatureSettingRecord>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        Ok(conn
            .query_row(
                "SELECT guild_id,key,enabled,config_json,revision,updated_at,updated_by FROM feature_settings WHERE guild_id=?1 AND key=?2",
                params![guild_id, key],
                |row| {
                    Ok(FeatureSettingRecord {
                        guild_id: row.get(0)?,
                        key: row.get(1)?,
                        enabled: row.get::<_, i64>(2)? != 0,
                        config_json: row.get(3)?,
                        revision: row.get::<_, i64>(4)?.try_into().unwrap_or(0),
                        updated_at: row.get(5)?,
                        updated_by: row.get(6)?,
                    })
                },
            )
            .optional()?)
    }

    pub fn enabled_feature_settings(&self, key: &str) -> Result<Vec<FeatureSettingRecord>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let mut stmt = conn.prepare(
            "SELECT guild_id,key,enabled,config_json,revision,updated_at,updated_by FROM feature_settings WHERE key=?1 AND enabled=1 ORDER BY updated_at ASC",
        )?;
        let rows = stmt.query_map([key], |row| {
            Ok(FeatureSettingRecord {
                guild_id: row.get(0)?,
                key: row.get(1)?,
                enabled: row.get::<_, i64>(2)? != 0,
                config_json: row.get(3)?,
                revision: row.get::<_, i64>(4)?.try_into().unwrap_or(0),
                updated_at: row.get(5)?,
                updated_by: row.get(6)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Return the latest setting for every guild, including disabled rows.
    ///
    /// Workers that own reversible Discord state (for example the Helper
    /// nickname) need to observe the transition from enabled to disabled in
    /// order to undo the previously applied projection.  Filtering these
    /// rows out would leave stale state behind forever.
    pub fn feature_settings(&self, key: &str) -> Result<Vec<FeatureSettingRecord>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let mut stmt = conn.prepare(
            "SELECT guild_id,key,enabled,config_json,revision,updated_at,updated_by FROM feature_settings WHERE key=?1 ORDER BY updated_at ASC",
        )?;
        let rows = stmt.query_map([key], |row| {
            Ok(FeatureSettingRecord {
                guild_id: row.get(0)?,
                key: row.get(1)?,
                enabled: row.get::<_, i64>(2)? != 0,
                config_json: row.get(3)?,
                revision: row.get::<_, i64>(4)?.try_into().unwrap_or(0),
                updated_at: row.get(5)?,
                updated_by: row.get(6)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn feature_revision(
        &self,
        guild_id: &str,
        key: &str,
        revision: u64,
    ) -> Result<Option<FeatureSettingRecord>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        Ok(conn
            .query_row(
                "SELECT ?1,?2,enabled,config_json,revision,updated_at,updated_by FROM feature_revisions WHERE guild_id=?1 AND key=?2 AND revision=?3",
                params![guild_id, key, i64::try_from(revision).unwrap_or(i64::MAX)],
                |row| {
                    Ok(FeatureSettingRecord {
                        guild_id: row.get(0)?,
                        key: row.get(1)?,
                        enabled: row.get::<_, i64>(2)? != 0,
                        config_json: row.get(3)?,
                        revision: row.get::<_, i64>(4)?.try_into().unwrap_or(0),
                        updated_at: row.get(5)?,
                        updated_by: row.get(6)?,
                    })
                },
            )
            .optional()?)
    }

    pub fn feature_revisions(
        &self,
        guild_id: &str,
        key: &str,
        limit: u32,
    ) -> Result<Vec<FeatureSettingRecord>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let mut stmt = conn.prepare(
            "SELECT ?1,?2,enabled,config_json,revision,updated_at,updated_by FROM feature_revisions WHERE guild_id=?1 AND key=?2 ORDER BY revision DESC LIMIT ?3",
        )?;
        let rows = stmt.query_map(params![guild_id, key, i64::from(limit.min(100))], |row| {
            Ok(FeatureSettingRecord {
                guild_id: row.get(0)?,
                key: row.get(1)?,
                enabled: row.get::<_, i64>(2)? != 0,
                config_json: row.get(3)?,
                revision: row.get::<_, i64>(4)?.try_into().unwrap_or(0),
                updated_at: row.get(5)?,
                updated_by: row.get(6)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Publishes a feature and all of its runtime projections atomically.
    /// `expected_revision` prevents a stale panel tab from overwriting a
    /// newer change made by another moderator.
    #[allow(clippy::too_many_arguments)]
    pub fn publish_feature_setting(
        &self,
        guild_id: &str,
        key: &str,
        enabled: bool,
        config_json: &str,
        expected_revision: Option<u64>,
        updated_by: &str,
        projections: &[(String, String)],
    ) -> Result<FeatureSettingRecord> {
        let mut conn = self.conn.lock().expect("store mutex poisoned");
        let tx = conn.transaction()?;
        let record = Self::publish_feature_setting_on_tx(
            &tx,
            guild_id,
            key,
            enabled,
            config_json,
            expected_revision,
            updated_by,
            projections,
        )?;
        tx.commit()?;
        Ok(record)
    }

    #[allow(clippy::too_many_arguments)]
    fn publish_feature_setting_on_tx(
        tx: &rusqlite::Transaction<'_>,
        guild_id: &str,
        key: &str,
        enabled: bool,
        config_json: &str,
        expected_revision: Option<u64>,
        updated_by: &str,
        projections: &[(String, String)],
    ) -> Result<FeatureSettingRecord> {
        let current: Option<(i64, i64, String, String)> = tx
            .query_row(
                "SELECT revision,enabled,config_json,updated_by FROM feature_settings WHERE guild_id=?1 AND key=?2",
                params![guild_id, key],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        let current_revision = current
            .as_ref()
            .and_then(|item| u64::try_from(item.0).ok())
            .unwrap_or(0);
        if expected_revision.is_some_and(|value| value != current_revision) {
            bail!("feature_revision_conflict:{current_revision}");
        }
        let next_revision = current_revision.saturating_add(1);
        let now = Utc::now().timestamp_millis();
        if key == "community.achievements" && !enabled {
            tx.execute("INSERT INTO achievement_activity(guild_id,user_id,kind,value) SELECT guild_id,user_id,'voice',MIN(36000,MAX(0,?2-started_at)) FROM achievement_voice WHERE guild_id=?1 ON CONFLICT(guild_id,user_id,kind) DO UPDATE SET value=MIN(36000,value+excluded.value)",params![guild_id,now/1000])?;
            tx.execute(
                "DELETE FROM achievement_voice WHERE guild_id=?1",
                params![guild_id],
            )?;
            tx.execute(
                "DELETE FROM achievement_links WHERE guild_id=?1",
                params![guild_id],
            )?;
        }
        if key == "support.welcome" {
            tx.execute("INSERT INTO settings(guild_id,key,value,updated_at) VALUES(?1,'support.welcome.unified','true',?2) ON CONFLICT(guild_id,key) DO UPDATE SET value='true',updated_at=excluded.updated_at", params![guild_id, now])?;
        }
        tx.execute(
            "INSERT INTO feature_settings(guild_id,key,enabled,config_json,revision,updated_at,updated_by) VALUES(?1,?2,?3,?4,?5,?6,?7) ON CONFLICT(guild_id,key) DO UPDATE SET enabled=excluded.enabled,config_json=excluded.config_json,revision=excluded.revision,updated_at=excluded.updated_at,updated_by=excluded.updated_by",
            params![guild_id, key, if enabled { 1_i64 } else { 0_i64 }, config_json, i64::try_from(next_revision).unwrap_or(i64::MAX), now, updated_by],
        )?;
        tx.execute(
            "INSERT INTO feature_revisions(guild_id,key,revision,enabled,config_json,updated_at,updated_by) VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![guild_id, key, i64::try_from(next_revision).unwrap_or(i64::MAX), if enabled { 1_i64 } else { 0_i64 }, config_json, now, updated_by],
        )?;
        for (projection_key, projection_value) in projections {
            tx.execute(
                "INSERT INTO settings(guild_id,key,value,updated_at) VALUES(?1,?2,?3,?4) ON CONFLICT(guild_id,key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at",
                params![guild_id, projection_key, projection_value, now],
            )?;
        }
        let correlation_id = Uuid::new_v4().to_string();
        let before_json = current
            .as_ref()
            .map(|item| serde_json::json!({"enabled": item.1 != 0, "config": item.2, "revision": item.0}))
            .unwrap_or_else(|| serde_json::json!({}));
        let after_json = serde_json::json!({"enabled": enabled, "config": serde_json::from_str::<serde_json::Value>(config_json).unwrap_or_else(|_| serde_json::json!({})), "revision": next_revision});
        tx.execute(
            "INSERT INTO audit_events(correlation_id,guild_id,actor_id,action,reason,before_json,after_json,outcome,created_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![correlation_id, guild_id, updated_by, "feature.publish", key, before_json.to_string(), after_json.to_string(), "published", now],
        )?;
        Ok(FeatureSettingRecord {
            guild_id: guild_id.to_string(),
            key: key.to_string(),
            enabled,
            config_json: config_json.to_string(),
            revision: next_revision,
            updated_at: now,
            updated_by: updated_by.to_string(),
        })
    }

    /// Publishes the YouTube feature and its subscription projection in the
    /// same SQLite transaction. This keeps a stale revision or a failed
    /// subscription write from leaving the panel and worker out of sync.
    #[allow(clippy::too_many_arguments)]
    pub fn publish_youtube_feature_setting(
        &self,
        guild_id: &str,
        key: &str,
        enabled: bool,
        config_json: &str,
        expected_revision: Option<u64>,
        updated_by: &str,
        projections: &[(String, String)],
        subscription: Option<&YouTubeSubscriptionWrite>,
    ) -> Result<FeatureSettingRecord> {
        let mut conn = self.conn.lock().expect("store mutex poisoned");
        let tx = conn.transaction()?;
        let record = Self::publish_youtube_feature_setting_on_tx(
            &tx,
            guild_id,
            key,
            enabled,
            config_json,
            expected_revision,
            updated_by,
            projections,
            subscription,
        )?;
        tx.commit()?;
        Ok(record)
    }

    #[allow(clippy::too_many_arguments)]
    fn publish_youtube_feature_setting_on_tx(
        tx: &rusqlite::Transaction<'_>,
        guild_id: &str,
        key: &str,
        enabled: bool,
        config_json: &str,
        expected_revision: Option<u64>,
        updated_by: &str,
        projections: &[(String, String)],
        subscription: Option<&YouTubeSubscriptionWrite>,
    ) -> Result<FeatureSettingRecord> {
        let current: Option<(i64, i64, String, String)> = tx
            .query_row(
                "SELECT revision,enabled,config_json,updated_by FROM feature_settings WHERE guild_id=?1 AND key=?2",
                params![guild_id, key],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        let current_revision = current
            .as_ref()
            .and_then(|item| u64::try_from(item.0).ok())
            .unwrap_or(0);
        if expected_revision.is_some_and(|value| value != current_revision) {
            bail!("feature_revision_conflict:{current_revision}");
        }
        let next_revision = current_revision.saturating_add(1);
        let now = Utc::now().timestamp_millis();
        tx.execute(
            "INSERT INTO feature_settings(guild_id,key,enabled,config_json,revision,updated_at,updated_by) VALUES(?1,?2,?3,?4,?5,?6,?7) ON CONFLICT(guild_id,key) DO UPDATE SET enabled=excluded.enabled,config_json=excluded.config_json,revision=excluded.revision,updated_at=excluded.updated_at,updated_by=excluded.updated_by",
            params![guild_id, key, if enabled { 1_i64 } else { 0_i64 }, config_json, i64::try_from(next_revision).unwrap_or(i64::MAX), now, updated_by],
        )?;
        tx.execute(
            "INSERT INTO feature_revisions(guild_id,key,revision,enabled,config_json,updated_at,updated_by) VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![guild_id, key, i64::try_from(next_revision).unwrap_or(i64::MAX), if enabled { 1_i64 } else { 0_i64 }, config_json, now, updated_by],
        )?;
        for (projection_key, projection_value) in projections {
            tx.execute(
                "INSERT INTO settings(guild_id,key,value,updated_at) VALUES(?1,?2,?3,?4) ON CONFLICT(guild_id,key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at",
                params![guild_id, projection_key, projection_value, now],
            )?;
        }
        if let Some(subscription) = subscription {
            let existing_id: Option<i64> = tx
                .query_row(
                    "SELECT id FROM youtube_subscriptions WHERE guild_id=?1 ORDER BY updated_at DESC, id DESC LIMIT 1",
                    [guild_id],
                    |row| row.get(0),
                )
                .optional()?;
            if let Some(id) = existing_id {
                tx.execute(
                    "UPDATE youtube_subscriptions SET source_channel_id=?2,target_channel_id=?3,message_template=?4,mention=?5,enabled=?6,interval_seconds=?7,last_video_id=NULL,next_poll_at=?8,failure_count=0,last_error=NULL,updated_at=?8 WHERE guild_id=?1 AND id=?9",
                    params![guild_id, subscription.source_channel_id, subscription.target_channel_id, subscription.message_template, subscription.mention, if subscription.enabled { 1_i64 } else { 0_i64 }, subscription.interval_seconds, now, id],
                )?;
            } else if subscription.enabled {
                tx.execute(
                    "INSERT INTO youtube_subscriptions(guild_id,source_channel_id,target_channel_id,message_template,mention,enabled,interval_seconds,next_poll_at,created_by,created_at,updated_at) VALUES(?1,?2,?3,?4,?5,1,?6,?7,?8,?7,?7)",
                    params![guild_id, subscription.source_channel_id, subscription.target_channel_id, subscription.message_template, subscription.mention, subscription.interval_seconds, now, subscription.created_by],
                )?;
            }
        } else if !enabled {
            // Disabling from the feature editor does not carry a provider
            // payload. Stop every guild subscription in the same transaction
            // so a stale worker can never keep delivering alerts.
            tx.execute(
                "UPDATE youtube_subscriptions SET enabled=0,updated_at=?2 WHERE guild_id=?1",
                params![guild_id, now],
            )?;
        }
        let correlation_id = Uuid::new_v4().to_string();
        let before_json = current
            .as_ref()
            .map(|item| serde_json::json!({"enabled": item.1 != 0, "config": item.2, "revision": item.0}))
            .unwrap_or_else(|| serde_json::json!({}));
        let after_json = serde_json::json!({"enabled": enabled, "config": serde_json::from_str::<serde_json::Value>(config_json).unwrap_or_else(|_| serde_json::json!({})), "revision": next_revision});
        tx.execute(
            "INSERT INTO audit_events(correlation_id,guild_id,actor_id,action,reason,before_json,after_json,outcome,created_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![correlation_id, guild_id, updated_by, "feature.publish", key, before_json.to_string(), after_json.to_string(), "published", now],
        )?;
        Ok(FeatureSettingRecord {
            guild_id: guild_id.to_string(),
            key: key.to_string(),
            enabled,
            config_json: config_json.to_string(),
            revision: next_revision,
            updated_at: now,
            updated_by: updated_by.to_string(),
        })
    }

    /// Publishes the RSS feature and its subscription projection atomically.
    #[allow(clippy::too_many_arguments)]
    pub fn publish_rss_feature_setting(
        &self,
        guild_id: &str,
        key: &str,
        enabled: bool,
        config_json: &str,
        expected_revision: Option<u64>,
        updated_by: &str,
        projections: &[(String, String)],
        subscription: Option<&RssSubscriptionWrite>,
    ) -> Result<FeatureSettingRecord> {
        let mut conn = self.conn.lock().expect("store mutex poisoned");
        let tx = conn.transaction()?;
        let record = Self::publish_rss_feature_setting_on_tx(
            &tx,
            guild_id,
            key,
            enabled,
            config_json,
            expected_revision,
            updated_by,
            projections,
            subscription,
        )?;
        tx.commit()?;
        Ok(record)
    }

    #[allow(clippy::too_many_arguments)]
    fn publish_rss_feature_setting_on_tx(
        tx: &rusqlite::Transaction<'_>,
        guild_id: &str,
        key: &str,
        enabled: bool,
        config_json: &str,
        expected_revision: Option<u64>,
        updated_by: &str,
        projections: &[(String, String)],
        subscription: Option<&RssSubscriptionWrite>,
    ) -> Result<FeatureSettingRecord> {
        let current: Option<(i64, i64, String, String)> = tx
            .query_row(
                "SELECT revision,enabled,config_json,updated_by FROM feature_settings WHERE guild_id=?1 AND key=?2",
                params![guild_id, key],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        let current_revision = current
            .as_ref()
            .and_then(|item| u64::try_from(item.0).ok())
            .unwrap_or(0);
        if expected_revision.is_some_and(|value| value != current_revision) {
            bail!("feature_revision_conflict:{current_revision}");
        }
        let next_revision = current_revision.saturating_add(1);
        let now = Utc::now().timestamp_millis();
        tx.execute(
            "INSERT INTO feature_settings(guild_id,key,enabled,config_json,revision,updated_at,updated_by) VALUES(?1,?2,?3,?4,?5,?6,?7) ON CONFLICT(guild_id,key) DO UPDATE SET enabled=excluded.enabled,config_json=excluded.config_json,revision=excluded.revision,updated_at=excluded.updated_at,updated_by=excluded.updated_by",
            params![guild_id, key, if enabled { 1_i64 } else { 0_i64 }, config_json, i64::try_from(next_revision).unwrap_or(i64::MAX), now, updated_by],
        )?;
        tx.execute(
            "INSERT INTO feature_revisions(guild_id,key,revision,enabled,config_json,updated_at,updated_by) VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![guild_id, key, i64::try_from(next_revision).unwrap_or(i64::MAX), if enabled { 1_i64 } else { 0_i64 }, config_json, now, updated_by],
        )?;
        for (projection_key, projection_value) in projections {
            tx.execute(
                "INSERT INTO settings(guild_id,key,value,updated_at) VALUES(?1,?2,?3,?4) ON CONFLICT(guild_id,key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at",
                params![guild_id, projection_key, projection_value, now],
            )?;
        }
        if let Some(subscription) = subscription {
            let existing_id: Option<i64> = tx
                .query_row(
                    "SELECT id FROM rss_subscriptions WHERE guild_id=?1 ORDER BY updated_at DESC, id DESC LIMIT 1",
                    [guild_id],
                    |row| row.get(0),
                )
                .optional()?;
            if let Some(id) = existing_id {
                tx.execute(
                    "UPDATE rss_subscriptions SET feed_url=?2,target_channel_id=?3,message_template=?4,mention=?5,enabled=?6,interval_seconds=?7,last_item_id=NULL,next_poll_at=?8,failure_count=0,last_error=NULL,updated_at=?8 WHERE guild_id=?1 AND id=?9",
                    params![guild_id, subscription.feed_url, subscription.target_channel_id, subscription.message_template, subscription.mention, if subscription.enabled { 1_i64 } else { 0_i64 }, subscription.interval_seconds, now, id],
                )?;
            } else if subscription.enabled {
                tx.execute(
                    "INSERT INTO rss_subscriptions(guild_id,feed_url,target_channel_id,message_template,mention,enabled,interval_seconds,next_poll_at,created_by,created_at,updated_at) VALUES(?1,?2,?3,?4,?5,1,?6,?7,?8,?7,?7)",
                    params![guild_id, subscription.feed_url, subscription.target_channel_id, subscription.message_template, subscription.mention, subscription.interval_seconds, now, subscription.created_by],
                )?;
            }
        } else if !enabled {
            tx.execute(
                "UPDATE rss_subscriptions SET enabled=0,updated_at=?2 WHERE guild_id=?1",
                params![guild_id, now],
            )?;
        }
        let correlation_id = Uuid::new_v4().to_string();
        let before_json = current
            .as_ref()
            .map(|item| serde_json::json!({"enabled": item.1 != 0, "config": item.2, "revision": item.0}))
            .unwrap_or_else(|| serde_json::json!({}));
        let after_json = serde_json::json!({"enabled": enabled, "config": serde_json::from_str::<serde_json::Value>(config_json).unwrap_or_else(|_| serde_json::json!({})), "revision": next_revision});
        tx.execute(
            "INSERT INTO audit_events(correlation_id,guild_id,actor_id,action,reason,before_json,after_json,outcome,created_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![correlation_id, guild_id, updated_by, "feature.publish", key, before_json.to_string(), after_json.to_string(), "published", now],
        )?;
        Ok(FeatureSettingRecord {
            guild_id: guild_id.to_string(),
            key: key.to_string(),
            enabled,
            config_json: config_json.to_string(),
            revision: next_revision,
            updated_at: now,
            updated_by: updated_by.to_string(),
        })
    }

    /// Publishes the Bluesky alert feature and its polling subscription in one
    /// transaction so a revision can never report enabled while the worker is
    /// missing its source configuration.
    #[allow(clippy::too_many_arguments)]
    pub fn publish_bluesky_feature_setting(
        &self,
        guild_id: &str,
        key: &str,
        enabled: bool,
        config_json: &str,
        expected_revision: Option<u64>,
        updated_by: &str,
        projections: &[(String, String)],
        subscription: Option<&BlueskySubscriptionWrite>,
    ) -> Result<FeatureSettingRecord> {
        let mut conn = self.conn.lock().expect("store mutex poisoned");
        let tx = conn.transaction()?;
        let record = Self::publish_bluesky_feature_setting_on_tx(
            &tx,
            guild_id,
            key,
            enabled,
            config_json,
            expected_revision,
            updated_by,
            projections,
            subscription,
        )?;
        tx.commit()?;
        Ok(record)
    }

    #[allow(clippy::too_many_arguments)]
    fn publish_bluesky_feature_setting_on_tx(
        tx: &rusqlite::Transaction<'_>,
        guild_id: &str,
        key: &str,
        enabled: bool,
        config_json: &str,
        expected_revision: Option<u64>,
        updated_by: &str,
        projections: &[(String, String)],
        subscription: Option<&BlueskySubscriptionWrite>,
    ) -> Result<FeatureSettingRecord> {
        let current: Option<(i64, i64, String)> = tx
            .query_row(
                "SELECT revision,enabled,config_json FROM feature_settings WHERE guild_id=?1 AND key=?2",
                params![guild_id, key],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let current_revision = current
            .as_ref()
            .and_then(|item| u64::try_from(item.0).ok())
            .unwrap_or(0);
        if expected_revision.is_some_and(|value| value != current_revision) {
            bail!("feature_revision_conflict:{current_revision}");
        }
        let next_revision = current_revision.saturating_add(1);
        let now = Utc::now().timestamp_millis();
        tx.execute(
            "INSERT INTO feature_settings(guild_id,key,enabled,config_json,revision,updated_at,updated_by) VALUES(?1,?2,?3,?4,?5,?6,?7) ON CONFLICT(guild_id,key) DO UPDATE SET enabled=excluded.enabled,config_json=excluded.config_json,revision=excluded.revision,updated_at=excluded.updated_at,updated_by=excluded.updated_by",
            params![guild_id, key, if enabled { 1_i64 } else { 0_i64 }, config_json, i64::try_from(next_revision).unwrap_or(i64::MAX), now, updated_by],
        )?;
        tx.execute(
            "INSERT INTO feature_revisions(guild_id,key,revision,enabled,config_json,updated_at,updated_by) VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![guild_id, key, i64::try_from(next_revision).unwrap_or(i64::MAX), if enabled { 1_i64 } else { 0_i64 }, config_json, now, updated_by],
        )?;
        for (projection_key, projection_value) in projections {
            tx.execute(
                "INSERT INTO settings(guild_id,key,value,updated_at) VALUES(?1,?2,?3,?4) ON CONFLICT(guild_id,key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at",
                params![guild_id, projection_key, projection_value, now],
            )?;
        }
        if let Some(subscription) = subscription {
            let existing_id: Option<i64> = tx
                .query_row(
                    "SELECT id FROM bluesky_subscriptions WHERE guild_id=?1 ORDER BY updated_at DESC, id DESC LIMIT 1",
                    [guild_id],
                    |row| row.get(0),
                )
                .optional()?;
            if let Some(id) = existing_id {
                tx.execute(
                    "UPDATE bluesky_subscriptions SET source_handle=?2,target_channel_id=?3,message_template=?4,mention=?5,enabled=?6,interval_seconds=?7,last_post_uri=NULL,next_poll_at=?8,failure_count=0,last_error=NULL,updated_at=?8 WHERE guild_id=?1 AND id=?9",
                    params![guild_id, subscription.source_handle, subscription.target_channel_id, subscription.message_template, subscription.mention, if subscription.enabled { 1_i64 } else { 0_i64 }, subscription.interval_seconds, now, id],
                )?;
            } else if subscription.enabled {
                tx.execute(
                    "INSERT INTO bluesky_subscriptions(guild_id,source_handle,target_channel_id,message_template,mention,enabled,interval_seconds,next_poll_at,created_by,created_at,updated_at) VALUES(?1,?2,?3,?4,?5,1,?6,?7,?8,?7,?7)",
                    params![guild_id, subscription.source_handle, subscription.target_channel_id, subscription.message_template, subscription.mention, subscription.interval_seconds, now, subscription.created_by],
                )?;
            }
        } else if !enabled {
            tx.execute(
                "UPDATE bluesky_subscriptions SET enabled=0,updated_at=?2 WHERE guild_id=?1",
                params![guild_id, now],
            )?;
        }
        let correlation_id = Uuid::new_v4().to_string();
        let before_json = current
            .as_ref()
            .map(|item| serde_json::json!({"enabled": item.1 != 0, "config": item.2, "revision": item.0}))
            .unwrap_or_else(|| serde_json::json!({}));
        let after_json = serde_json::json!({"enabled": enabled, "config": serde_json::from_str::<serde_json::Value>(config_json).unwrap_or_else(|_| serde_json::json!({})), "revision": next_revision});
        tx.execute(
            "INSERT INTO audit_events(correlation_id,guild_id,actor_id,action,reason,before_json,after_json,outcome,created_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![correlation_id, guild_id, updated_by, "feature.publish", key, before_json.to_string(), after_json.to_string(), "published", now],
        )?;
        Ok(FeatureSettingRecord {
            guild_id: guild_id.to_string(),
            key: key.to_string(),
            enabled,
            config_json: config_json.to_string(),
            revision: next_revision,
            updated_at: now,
            updated_by: updated_by.to_string(),
        })
    }

    /// Publishes the Reddit alert feature and its polling subscription
    /// atomically. Reddit is kept on the same revision/projection contract as
    /// the other provider adapters so the panel can never report an enabled
    /// feature while the worker still has stale subscription settings.
    #[allow(clippy::too_many_arguments)]
    pub fn publish_reddit_feature_setting(
        &self,
        guild_id: &str,
        key: &str,
        enabled: bool,
        config_json: &str,
        expected_revision: Option<u64>,
        updated_by: &str,
        projections: &[(String, String)],
        subscription: Option<&RedditSubscriptionWrite>,
    ) -> Result<FeatureSettingRecord> {
        let mut conn = self.conn.lock().expect("store mutex poisoned");
        let tx = conn.transaction()?;
        let current: Option<(i64, i64, String)> = tx
            .query_row(
                "SELECT revision,enabled,config_json FROM feature_settings WHERE guild_id=?1 AND key=?2",
                params![guild_id, key],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let current_revision = current
            .as_ref()
            .and_then(|item| u64::try_from(item.0).ok())
            .unwrap_or(0);
        if expected_revision.is_some_and(|value| value != current_revision) {
            bail!("feature_revision_conflict:{current_revision}");
        }
        let next_revision = current_revision.saturating_add(1);
        let now = Utc::now().timestamp_millis();
        tx.execute(
            "INSERT INTO feature_settings(guild_id,key,enabled,config_json,revision,updated_at,updated_by) VALUES(?1,?2,?3,?4,?5,?6,?7) ON CONFLICT(guild_id,key) DO UPDATE SET enabled=excluded.enabled,config_json=excluded.config_json,revision=excluded.revision,updated_at=excluded.updated_at,updated_by=excluded.updated_by",
            params![guild_id, key, if enabled { 1_i64 } else { 0_i64 }, config_json, i64::try_from(next_revision).unwrap_or(i64::MAX), now, updated_by],
        )?;
        tx.execute(
            "INSERT INTO feature_revisions(guild_id,key,revision,enabled,config_json,updated_at,updated_by) VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![guild_id, key, i64::try_from(next_revision).unwrap_or(i64::MAX), if enabled { 1_i64 } else { 0_i64 }, config_json, now, updated_by],
        )?;
        for (projection_key, projection_value) in projections {
            tx.execute(
                "INSERT INTO settings(guild_id,key,value,updated_at) VALUES(?1,?2,?3,?4) ON CONFLICT(guild_id,key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at",
                params![guild_id, projection_key, projection_value, now],
            )?;
        }
        if let Some(subscription) = subscription {
            let existing_id: Option<i64> = tx
                .query_row(
                    "SELECT id FROM reddit_subscriptions WHERE guild_id=?1 ORDER BY updated_at DESC, id DESC LIMIT 1",
                    [guild_id],
                    |row| row.get(0),
                )
                .optional()?;
            if let Some(id) = existing_id {
                tx.execute(
                    "UPDATE reddit_subscriptions SET source_subreddit=?2,target_channel_id=?3,message_template=?4,mention=?5,enabled=?6,interval_seconds=?7,last_post_id=NULL,next_poll_at=?8,failure_count=0,last_error=NULL,updated_at=?8 WHERE guild_id=?1 AND id=?9",
                    params![guild_id, subscription.source_subreddit, subscription.target_channel_id, subscription.message_template, subscription.mention, if subscription.enabled { 1_i64 } else { 0_i64 }, subscription.interval_seconds, now, id],
                )?;
            } else if subscription.enabled {
                tx.execute(
                    "INSERT INTO reddit_subscriptions(guild_id,source_subreddit,target_channel_id,message_template,mention,enabled,interval_seconds,next_poll_at,created_by,created_at,updated_at) VALUES(?1,?2,?3,?4,?5,1,?6,?7,?8,?7,?7)",
                    params![guild_id, subscription.source_subreddit, subscription.target_channel_id, subscription.message_template, subscription.mention, subscription.interval_seconds, now, subscription.created_by],
                )?;
            }
        } else if !enabled {
            tx.execute(
                "UPDATE reddit_subscriptions SET enabled=0,updated_at=?2 WHERE guild_id=?1",
                params![guild_id, now],
            )?;
        }
        let correlation_id = Uuid::new_v4().to_string();
        let before_json = current
            .as_ref()
            .map(|item| serde_json::json!({"enabled": item.1 != 0, "config": item.2, "revision": item.0}))
            .unwrap_or_else(|| serde_json::json!({}));
        let after_json = serde_json::json!({"enabled": enabled, "config": serde_json::from_str::<serde_json::Value>(config_json).unwrap_or_else(|_| serde_json::json!({})), "revision": next_revision});
        tx.execute(
            "INSERT INTO audit_events(correlation_id,guild_id,actor_id,action,reason,before_json,after_json,outcome,created_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![correlation_id, guild_id, updated_by, "feature.publish", key, before_json.to_string(), after_json.to_string(), "published", now],
        )?;
        tx.commit()?;
        Ok(FeatureSettingRecord {
            guild_id: guild_id.to_string(),
            key: key.to_string(),
            enabled,
            config_json: config_json.to_string(),
            revision: next_revision,
            updated_at: now,
            updated_by: updated_by.to_string(),
        })
    }

    /// Publishes the X alert feature and its polling subscription atomically.
    #[allow(clippy::too_many_arguments)]
    pub fn publish_x_feature_setting(
        &self,
        guild_id: &str,
        key: &str,
        enabled: bool,
        config_json: &str,
        expected_revision: Option<u64>,
        updated_by: &str,
        projections: &[(String, String)],
        subscription: Option<&XSubscriptionWrite>,
    ) -> Result<FeatureSettingRecord> {
        let mut conn = self.conn.lock().expect("store mutex poisoned");
        let tx = conn.transaction()?;
        let current: Option<(i64, i64, String)> = tx
            .query_row(
                "SELECT revision,enabled,config_json FROM feature_settings WHERE guild_id=?1 AND key=?2",
                params![guild_id, key],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let current_revision = current
            .as_ref()
            .and_then(|item| u64::try_from(item.0).ok())
            .unwrap_or(0);
        if expected_revision.is_some_and(|value| value != current_revision) {
            bail!("feature_revision_conflict:{current_revision}");
        }
        let next_revision = current_revision.saturating_add(1);
        let now = Utc::now().timestamp_millis();
        tx.execute(
            "INSERT INTO feature_settings(guild_id,key,enabled,config_json,revision,updated_at,updated_by) VALUES(?1,?2,?3,?4,?5,?6,?7) ON CONFLICT(guild_id,key) DO UPDATE SET enabled=excluded.enabled,config_json=excluded.config_json,revision=excluded.revision,updated_at=excluded.updated_at,updated_by=excluded.updated_by",
            params![guild_id, key, if enabled { 1_i64 } else { 0_i64 }, config_json, i64::try_from(next_revision).unwrap_or(i64::MAX), now, updated_by],
        )?;
        tx.execute(
            "INSERT INTO feature_revisions(guild_id,key,revision,enabled,config_json,updated_at,updated_by) VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![guild_id, key, i64::try_from(next_revision).unwrap_or(i64::MAX), if enabled { 1_i64 } else { 0_i64 }, config_json, now, updated_by],
        )?;
        for (projection_key, projection_value) in projections {
            tx.execute(
                "INSERT INTO settings(guild_id,key,value,updated_at) VALUES(?1,?2,?3,?4) ON CONFLICT(guild_id,key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at",
                params![guild_id, projection_key, projection_value, now],
            )?;
        }
        if let Some(subscription) = subscription {
            let existing_id: Option<i64> = tx
                .query_row(
                    "SELECT id FROM x_subscriptions WHERE guild_id=?1 ORDER BY updated_at DESC, id DESC LIMIT 1",
                    [guild_id],
                    |row| row.get(0),
                )
                .optional()?;
            if let Some(id) = existing_id {
                tx.execute(
                    "UPDATE x_subscriptions SET source_handle=?2,target_channel_id=?3,message_template=?4,mention=?5,enabled=?6,interval_seconds=?7,last_post_id=NULL,next_poll_at=?8,failure_count=0,last_error=NULL,updated_at=?8 WHERE guild_id=?1 AND id=?9",
                    params![guild_id, subscription.source_handle, subscription.target_channel_id, subscription.message_template, subscription.mention, if subscription.enabled { 1_i64 } else { 0_i64 }, subscription.interval_seconds, now, id],
                )?;
            } else if subscription.enabled {
                tx.execute(
                    "INSERT INTO x_subscriptions(guild_id,source_handle,target_channel_id,message_template,mention,enabled,interval_seconds,next_poll_at,created_by,created_at,updated_at) VALUES(?1,?2,?3,?4,?5,1,?6,?7,?8,?7,?7)",
                    params![guild_id, subscription.source_handle, subscription.target_channel_id, subscription.message_template, subscription.mention, subscription.interval_seconds, now, subscription.created_by],
                )?;
            }
        } else if !enabled {
            tx.execute(
                "UPDATE x_subscriptions SET enabled=0,updated_at=?2 WHERE guild_id=?1",
                params![guild_id, now],
            )?;
        }
        let correlation_id = Uuid::new_v4().to_string();
        let before_json = current
            .as_ref()
            .map(|item| serde_json::json!({"enabled": item.1 != 0, "config": item.2, "revision": item.0}))
            .unwrap_or_else(|| serde_json::json!({}));
        let after_json = serde_json::json!({"enabled": enabled, "config": serde_json::from_str::<serde_json::Value>(config_json).unwrap_or_else(|_| serde_json::json!({})), "revision": next_revision});
        tx.execute(
            "INSERT INTO audit_events(correlation_id,guild_id,actor_id,action,reason,before_json,after_json,outcome,created_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![correlation_id, guild_id, updated_by, "feature.publish", key, before_json.to_string(), after_json.to_string(), "published", now],
        )?;
        tx.commit()?;
        Ok(FeatureSettingRecord {
            guild_id: guild_id.to_string(),
            key: key.to_string(),
            enabled,
            config_json: config_json.to_string(),
            revision: next_revision,
            updated_at: now,
            updated_by: updated_by.to_string(),
        })
    }

    /// Publishes TikTok configuration and its creator subscription atomically.
    #[allow(clippy::too_many_arguments)]
    pub fn publish_tiktok_feature_setting(
        &self,
        guild_id: &str,
        key: &str,
        enabled: bool,
        config_json: &str,
        expected_revision: Option<u64>,
        updated_by: &str,
        projections: &[(String, String)],
        subscription: Option<&TikTokSubscriptionWrite>,
    ) -> Result<FeatureSettingRecord> {
        let mut conn = self.conn.lock().expect("store mutex poisoned");
        let tx = conn.transaction()?;
        let record = Self::publish_tiktok_feature_setting_on_tx(
            &tx,
            guild_id,
            key,
            enabled,
            config_json,
            expected_revision,
            updated_by,
            projections,
            subscription,
        )?;
        tx.commit()?;
        Ok(record)
    }

    #[allow(clippy::too_many_arguments)]
    fn publish_tiktok_feature_setting_on_tx(
        tx: &rusqlite::Transaction<'_>,
        guild_id: &str,
        key: &str,
        enabled: bool,
        config_json: &str,
        expected_revision: Option<u64>,
        updated_by: &str,
        projections: &[(String, String)],
        subscription: Option<&TikTokSubscriptionWrite>,
    ) -> Result<FeatureSettingRecord> {
        let current: Option<(i64, i64, String)> = tx
            .query_row(
                "SELECT revision,enabled,config_json FROM feature_settings WHERE guild_id=?1 AND key=?2",
                params![guild_id, key],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let current_revision = current
            .as_ref()
            .and_then(|item| u64::try_from(item.0).ok())
            .unwrap_or(0);
        if expected_revision.is_some_and(|value| value != current_revision) {
            bail!("feature_revision_conflict:{current_revision}");
        }
        let next_revision = current_revision.saturating_add(1);
        let now = Utc::now().timestamp_millis();
        tx.execute(
            "INSERT INTO feature_settings(guild_id,key,enabled,config_json,revision,updated_at,updated_by) VALUES(?1,?2,?3,?4,?5,?6,?7) ON CONFLICT(guild_id,key) DO UPDATE SET enabled=excluded.enabled,config_json=excluded.config_json,revision=excluded.revision,updated_at=excluded.updated_at,updated_by=excluded.updated_by",
            params![guild_id, key, if enabled { 1_i64 } else { 0_i64 }, config_json, i64::try_from(next_revision).unwrap_or(i64::MAX), now, updated_by],
        )?;
        tx.execute(
            "INSERT INTO feature_revisions(guild_id,key,revision,enabled,config_json,updated_at,updated_by) VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![guild_id, key, i64::try_from(next_revision).unwrap_or(i64::MAX), if enabled { 1_i64 } else { 0_i64 }, config_json, now, updated_by],
        )?;
        for (projection_key, projection_value) in projections {
            tx.execute(
                "INSERT INTO settings(guild_id,key,value,updated_at) VALUES(?1,?2,?3,?4) ON CONFLICT(guild_id,key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at",
                params![guild_id, projection_key, projection_value, now],
            )?;
        }
        if let Some(subscription) = subscription {
            let existing_id: Option<i64> = tx.query_row(
                "SELECT id FROM tiktok_subscriptions WHERE guild_id=?1 ORDER BY updated_at DESC, id DESC LIMIT 1",
                [guild_id], |row| row.get(0),
            ).optional()?;
            if let Some(id) = existing_id {
                tx.execute(
                    "UPDATE tiktok_subscriptions SET source_label=?2,target_channel_id=?3,message_template=?4,mention=?5,enabled=?6,interval_seconds=?7,last_video_id=NULL,next_poll_at=?8,failure_count=0,last_error=NULL,updated_at=?8 WHERE guild_id=?1 AND id=?9",
                    params![guild_id, subscription.source_label, subscription.target_channel_id, subscription.message_template, subscription.mention, if subscription.enabled { 1_i64 } else { 0_i64 }, subscription.interval_seconds, now, id],
                )?;
            } else if subscription.enabled {
                tx.execute(
                    "INSERT INTO tiktok_subscriptions(guild_id,source_label,target_channel_id,message_template,mention,enabled,interval_seconds,next_poll_at,created_by,created_at,updated_at) VALUES(?1,?2,?3,?4,?5,1,?6,?7,?8,?7,?7)",
                    params![guild_id, subscription.source_label, subscription.target_channel_id, subscription.message_template, subscription.mention, subscription.interval_seconds, now, subscription.created_by],
                )?;
            }
        } else if !enabled {
            tx.execute(
                "UPDATE tiktok_subscriptions SET enabled=0,updated_at=?2 WHERE guild_id=?1",
                params![guild_id, now],
            )?;
        }
        let correlation_id = Uuid::new_v4().to_string();
        let before_json = current.as_ref().map(|item| serde_json::json!({"enabled": item.1 != 0, "config": item.2, "revision": item.0})).unwrap_or_else(|| serde_json::json!({}));
        let after_json = serde_json::json!({"enabled": enabled, "config": serde_json::from_str::<serde_json::Value>(config_json).unwrap_or_else(|_| serde_json::json!({})), "revision": next_revision});
        tx.execute(
            "INSERT INTO audit_events(correlation_id,guild_id,actor_id,action,reason,before_json,after_json,outcome,created_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![correlation_id, guild_id, updated_by, "feature.publish", key, before_json.to_string(), after_json.to_string(), "published", now],
        )?;
        Ok(FeatureSettingRecord {
            guild_id: guild_id.to_string(),
            key: key.to_string(),
            enabled,
            config_json: config_json.to_string(),
            revision: next_revision,
            updated_at: now,
            updated_by: updated_by.to_string(),
        })
    }

    pub fn youtube_subscriptions(&self, guild_id: &str) -> Result<Vec<YouTubeSubscriptionRecord>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let mut stmt = conn.prepare("SELECT id,guild_id,source_channel_id,target_channel_id,message_template,mention,enabled,interval_seconds,last_video_id,next_poll_at,failure_count,last_error,created_by,created_at,updated_at FROM youtube_subscriptions WHERE guild_id=?1 ORDER BY updated_at DESC, id DESC")?;
        let rows = stmt.query_map([guild_id], youtube_subscription_from_row)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_youtube_subscription(
        &self,
        guild_id: &str,
        source_channel_id: &str,
        target_channel_id: &str,
        message_template: &str,
        mention: &str,
        enabled: bool,
        interval_seconds: i64,
        created_by: &str,
    ) -> Result<YouTubeSubscriptionRecord> {
        let now = Utc::now().timestamp_millis();
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.execute("INSERT INTO youtube_subscriptions(guild_id,source_channel_id,target_channel_id,message_template,mention,enabled,interval_seconds,next_poll_at,created_by,created_at,updated_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?8,?8)", params![guild_id, source_channel_id, target_channel_id, message_template, mention, if enabled { 1_i64 } else { 0_i64 }, interval_seconds, now, created_by])
            .map_err(|error| if error.to_string().contains("UNIQUE") { anyhow!("youtube_subscription_exists") } else { error.into() })?;
        let id = conn.last_insert_rowid();
        conn.query_row("SELECT id,guild_id,source_channel_id,target_channel_id,message_template,mention,enabled,interval_seconds,last_video_id,next_poll_at,failure_count,last_error,created_by,created_at,updated_at FROM youtube_subscriptions WHERE id=?1", [id], youtube_subscription_from_row).map_err(Into::into)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn update_youtube_subscription(
        &self,
        guild_id: &str,
        id: i64,
        source_channel_id: &str,
        target_channel_id: &str,
        message_template: &str,
        mention: &str,
        enabled: bool,
        interval_seconds: i64,
    ) -> Result<Option<YouTubeSubscriptionRecord>> {
        let now = Utc::now().timestamp_millis();
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.execute("UPDATE youtube_subscriptions SET source_channel_id=?3,target_channel_id=?4,message_template=?5,mention=?6,enabled=?7,interval_seconds=?8,updated_at=?9 WHERE guild_id=?1 AND id=?2", params![guild_id, id, source_channel_id, target_channel_id, message_template, mention, if enabled { 1_i64 } else { 0_i64 }, interval_seconds, now])?;
        conn.query_row("SELECT id,guild_id,source_channel_id,target_channel_id,message_template,mention,enabled,interval_seconds,last_video_id,next_poll_at,failure_count,last_error,created_by,created_at,updated_at FROM youtube_subscriptions WHERE guild_id=?1 AND id=?2", params![guild_id, id], youtube_subscription_from_row).optional()?.map_or(Ok(None), |record| Ok(Some(record)))
    }

    pub fn delete_youtube_subscription(&self, guild_id: &str, id: i64) -> Result<bool> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        Ok(conn.execute(
            "DELETE FROM youtube_subscriptions WHERE guild_id=?1 AND id=?2",
            params![guild_id, id],
        )? > 0)
    }

    pub fn due_youtube_subscriptions(
        &self,
        now_ms: i64,
        limit: u32,
    ) -> Result<Vec<YouTubeSubscriptionRecord>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let mut stmt = conn.prepare("SELECT id,guild_id,source_channel_id,target_channel_id,message_template,mention,enabled,interval_seconds,last_video_id,next_poll_at,failure_count,last_error,created_by,created_at,updated_at FROM youtube_subscriptions WHERE enabled=1 AND next_poll_at<=?1 ORDER BY next_poll_at ASC LIMIT ?2")?;
        let rows = stmt.query_map(
            params![now_ms, i64::from(limit.min(100))],
            youtube_subscription_from_row,
        )?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn update_youtube_poll(
        &self,
        id: i64,
        last_video_id: Option<&str>,
        next_poll_at: i64,
        failure_count: i64,
        last_error: Option<&str>,
    ) -> Result<()> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.execute("UPDATE youtube_subscriptions SET last_video_id=?2,next_poll_at=?3,failure_count=?4,last_error=?5,updated_at=?3 WHERE id=?1", params![id, last_video_id, next_poll_at, failure_count, last_error])?;
        Ok(())
    }

    /// Publishes the Twitch feature and its EventSub delivery projection atomically.
    #[allow(clippy::too_many_arguments)]
    pub fn publish_twitch_feature_setting(
        &self,
        guild_id: &str,
        key: &str,
        enabled: bool,
        config_json: &str,
        expected_revision: Option<u64>,
        updated_by: &str,
        projections: &[(String, String)],
        subscription: Option<&TwitchSubscriptionWrite>,
    ) -> Result<FeatureSettingRecord> {
        let mut conn = self.conn.lock().expect("store mutex poisoned");
        let tx = conn.transaction()?;
        let record = Self::publish_twitch_feature_setting_on_tx(
            &tx,
            guild_id,
            key,
            enabled,
            config_json,
            expected_revision,
            updated_by,
            projections,
            subscription,
        )?;
        tx.commit()?;
        Ok(record)
    }

    #[allow(clippy::too_many_arguments)]
    fn publish_twitch_feature_setting_on_tx(
        tx: &rusqlite::Transaction<'_>,
        guild_id: &str,
        key: &str,
        enabled: bool,
        config_json: &str,
        expected_revision: Option<u64>,
        updated_by: &str,
        projections: &[(String, String)],
        subscription: Option<&TwitchSubscriptionWrite>,
    ) -> Result<FeatureSettingRecord> {
        let current: Option<(i64, i64, String, String)> = tx
            .query_row(
                "SELECT revision,enabled,config_json,updated_by FROM feature_settings WHERE guild_id=?1 AND key=?2",
                params![guild_id, key],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        let current_revision = current
            .as_ref()
            .and_then(|item| u64::try_from(item.0).ok())
            .unwrap_or(0);
        if expected_revision.is_some_and(|value| value != current_revision) {
            bail!("feature_revision_conflict:{current_revision}");
        }
        let next_revision = current_revision.saturating_add(1);
        let now = Utc::now().timestamp_millis();
        tx.execute(
            "INSERT INTO feature_settings(guild_id,key,enabled,config_json,revision,updated_at,updated_by) VALUES(?1,?2,?3,?4,?5,?6,?7) ON CONFLICT(guild_id,key) DO UPDATE SET enabled=excluded.enabled,config_json=excluded.config_json,revision=excluded.revision,updated_at=excluded.updated_at,updated_by=excluded.updated_by",
            params![guild_id, key, if enabled { 1_i64 } else { 0_i64 }, config_json, i64::try_from(next_revision).unwrap_or(i64::MAX), now, updated_by],
        )?;
        tx.execute(
            "INSERT INTO feature_revisions(guild_id,key,revision,enabled,config_json,updated_at,updated_by) VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![guild_id, key, i64::try_from(next_revision).unwrap_or(i64::MAX), if enabled { 1_i64 } else { 0_i64 }, config_json, now, updated_by],
        )?;
        for (projection_key, projection_value) in projections {
            tx.execute(
                "INSERT INTO settings(guild_id,key,value,updated_at) VALUES(?1,?2,?3,?4) ON CONFLICT(guild_id,key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at",
                params![guild_id, projection_key, projection_value, now],
            )?;
        }
        if let Some(subscription) = subscription {
            let existing_id: Option<i64> = tx
                .query_row(
                    "SELECT id FROM twitch_subscriptions WHERE guild_id=?1 ORDER BY updated_at DESC, id DESC LIMIT 1",
                    [guild_id],
                    |row| row.get(0),
                )
                .optional()?;
            if let Some(id) = existing_id {
                tx.execute(
                    "UPDATE twitch_subscriptions SET source_login=?2,source_user_id=?3,target_channel_id=?4,message_template=?5,mention=?6,enabled=?7,pending_event_id=NULL,pending_stream_id=NULL,pending_started_at=NULL,last_event_id=NULL,next_poll_at=?8,failure_count=0,last_error=NULL,updated_at=?8 WHERE guild_id=?1 AND id=?9",
                    params![guild_id, subscription.source_login, subscription.source_user_id, subscription.target_channel_id, subscription.message_template, subscription.mention, if subscription.enabled { 1_i64 } else { 0_i64 }, i64::MAX, id],
                )?;
            } else if subscription.enabled {
                tx.execute(
                    "INSERT INTO twitch_subscriptions(guild_id,source_login,source_user_id,target_channel_id,message_template,mention,enabled,next_poll_at,created_by,created_at,updated_at) VALUES(?1,?2,?3,?4,?5,?6,1,?7,?8,?9,?9)",
                    params![guild_id, subscription.source_login, subscription.source_user_id, subscription.target_channel_id, subscription.message_template, subscription.mention, i64::MAX, subscription.created_by, now],
                )?;
            }
        } else if !enabled {
            tx.execute(
                "UPDATE twitch_subscriptions SET enabled=0,updated_at=?2 WHERE guild_id=?1",
                params![guild_id, now],
            )?;
        }
        let correlation_id = Uuid::new_v4().to_string();
        let before_json = current
            .as_ref()
            .map(|item| serde_json::json!({"enabled": item.1 != 0, "config": item.2, "revision": item.0}))
            .unwrap_or_else(|| serde_json::json!({}));
        let after_json = serde_json::json!({"enabled": enabled, "config": serde_json::from_str::<serde_json::Value>(config_json).unwrap_or_else(|_| serde_json::json!({})), "revision": next_revision});
        tx.execute(
            "INSERT INTO audit_events(correlation_id,guild_id,actor_id,action,reason,before_json,after_json,outcome,created_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![correlation_id, guild_id, updated_by, "feature.publish", key, before_json.to_string(), after_json.to_string(), "published", now],
        )?;
        Ok(FeatureSettingRecord {
            guild_id: guild_id.to_string(),
            key: key.to_string(),
            enabled,
            config_json: config_json.to_string(),
            revision: next_revision,
            updated_at: now,
            updated_by: updated_by.to_string(),
        })
    }

    pub fn twitch_subscriptions(&self, guild_id: &str) -> Result<Vec<TwitchSubscriptionRecord>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let mut stmt = conn.prepare("SELECT id,guild_id,source_login,source_user_id,target_channel_id,message_template,mention,enabled,pending_event_id,pending_stream_id,pending_started_at,last_event_id,next_poll_at,failure_count,last_error,created_by,created_at,updated_at FROM twitch_subscriptions WHERE guild_id=?1 ORDER BY updated_at DESC, id DESC")?;
        let rows = stmt.query_map([guild_id], twitch_subscription_from_row)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_twitch_subscription(
        &self,
        guild_id: &str,
        source_login: &str,
        source_user_id: &str,
        target_channel_id: &str,
        message_template: &str,
        mention: &str,
        enabled: bool,
        created_by: &str,
    ) -> Result<TwitchSubscriptionRecord> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.execute("INSERT INTO twitch_subscriptions(guild_id,source_login,source_user_id,target_channel_id,message_template,mention,enabled,next_poll_at,created_by,created_at,updated_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?8,?8)", params![guild_id, source_login, source_user_id, target_channel_id, message_template, mention, if enabled { 1_i64 } else { 0_i64 }, i64::MAX, created_by])
            .map_err(|error| if error.to_string().contains("UNIQUE") { anyhow!("twitch_subscription_exists") } else { error.into() })?;
        let id = conn.last_insert_rowid();
        conn.query_row("SELECT id,guild_id,source_login,source_user_id,target_channel_id,message_template,mention,enabled,pending_event_id,pending_stream_id,pending_started_at,last_event_id,next_poll_at,failure_count,last_error,created_by,created_at,updated_at FROM twitch_subscriptions WHERE id=?1", [id], twitch_subscription_from_row).map_err(Into::into)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn update_twitch_subscription(
        &self,
        guild_id: &str,
        id: i64,
        source_login: &str,
        source_user_id: &str,
        target_channel_id: &str,
        message_template: &str,
        mention: &str,
        enabled: bool,
    ) -> Result<Option<TwitchSubscriptionRecord>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.execute("UPDATE twitch_subscriptions SET source_login=?3,source_user_id=?4,target_channel_id=?5,message_template=?6,mention=?7,enabled=?8,pending_event_id=NULL,pending_stream_id=NULL,pending_started_at=NULL,last_event_id=NULL,next_poll_at=?9,failure_count=0,last_error=NULL,updated_at=?9 WHERE guild_id=?1 AND id=?2", params![guild_id, id, source_login, source_user_id, target_channel_id, message_template, mention, if enabled { 1_i64 } else { 0_i64 }, i64::MAX])?;
        conn.query_row("SELECT id,guild_id,source_login,source_user_id,target_channel_id,message_template,mention,enabled,pending_event_id,pending_stream_id,pending_started_at,last_event_id,next_poll_at,failure_count,last_error,created_by,created_at,updated_at FROM twitch_subscriptions WHERE guild_id=?1 AND id=?2", params![guild_id, id], twitch_subscription_from_row).optional()?.map_or(Ok(None), |record| Ok(Some(record)))
    }

    pub fn delete_twitch_subscription(&self, guild_id: &str, id: i64) -> Result<bool> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        Ok(conn.execute(
            "DELETE FROM twitch_subscriptions WHERE guild_id=?1 AND id=?2",
            params![guild_id, id],
        )? > 0)
    }

    pub fn due_twitch_subscriptions(
        &self,
        now_ms: i64,
        limit: u32,
    ) -> Result<Vec<TwitchSubscriptionRecord>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let mut stmt = conn.prepare("SELECT id,guild_id,source_login,source_user_id,target_channel_id,message_template,mention,enabled,pending_event_id,pending_stream_id,pending_started_at,last_event_id,next_poll_at,failure_count,last_error,created_by,created_at,updated_at FROM twitch_subscriptions WHERE enabled=1 AND pending_event_id IS NOT NULL AND next_poll_at<=?1 ORDER BY next_poll_at ASC LIMIT ?2")?;
        let rows = stmt.query_map(
            params![now_ms, i64::from(limit.min(100))],
            twitch_subscription_from_row,
        )?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn stage_twitch_event(
        &self,
        source_user_id: &str,
        event_id: &str,
        stream_id: &str,
        started_at: &str,
    ) -> Result<usize> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let now = Utc::now().timestamp_millis();
        Ok(conn.execute("UPDATE twitch_subscriptions SET pending_event_id=?2,pending_stream_id=?3,pending_started_at=?4,next_poll_at=?5,failure_count=0,last_error=NULL,updated_at=?5 WHERE source_user_id=?1 AND enabled=1 AND (pending_event_id IS NULL OR pending_event_id<>?2) AND (last_event_id IS NULL OR last_event_id<>?2)", params![source_user_id, event_id, stream_id, started_at, now])?)
    }

    pub fn ack_twitch_event(
        &self,
        id: i64,
        event_id: &str,
        next_poll_at: i64,
        failure_count: i64,
        last_error: Option<&str>,
    ) -> Result<bool> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        Ok(conn.execute("UPDATE twitch_subscriptions SET pending_event_id=NULL,pending_stream_id=NULL,pending_started_at=NULL,last_event_id=?2,next_poll_at=?3,failure_count=?4,last_error=?5,updated_at=?3 WHERE id=?1 AND pending_event_id=?2", params![id, event_id, next_poll_at, failure_count, last_error])? > 0)
    }

    pub fn retry_twitch_event(
        &self,
        id: i64,
        event_id: &str,
        next_poll_at: i64,
        failure_count: i64,
        last_error: Option<&str>,
    ) -> Result<bool> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        Ok(conn.execute("UPDATE twitch_subscriptions SET next_poll_at=?3,failure_count=?4,last_error=?5,updated_at=?3 WHERE id=?1 AND pending_event_id=?2", params![id, event_id, next_poll_at, failure_count, last_error])? > 0)
    }

    pub fn rss_subscriptions(&self, guild_id: &str) -> Result<Vec<RssSubscriptionRecord>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let mut stmt = conn.prepare("SELECT id,guild_id,feed_url,target_channel_id,message_template,mention,enabled,interval_seconds,last_item_id,next_poll_at,failure_count,last_error,created_by,created_at,updated_at FROM rss_subscriptions WHERE guild_id=?1 ORDER BY updated_at DESC, id DESC")?;
        let rows = stmt.query_map([guild_id], rss_subscription_from_row)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_rss_subscription(
        &self,
        guild_id: &str,
        feed_url: &str,
        target_channel_id: &str,
        message_template: &str,
        mention: &str,
        enabled: bool,
        interval_seconds: i64,
        created_by: &str,
    ) -> Result<RssSubscriptionRecord> {
        let now = Utc::now().timestamp_millis();
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.execute("INSERT INTO rss_subscriptions(guild_id,feed_url,target_channel_id,message_template,mention,enabled,interval_seconds,next_poll_at,created_by,created_at,updated_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?8,?8)", params![guild_id, feed_url, target_channel_id, message_template, mention, if enabled { 1_i64 } else { 0_i64 }, interval_seconds, now, created_by])
            .map_err(|error| if error.to_string().contains("UNIQUE") { anyhow!("rss_subscription_exists") } else { error.into() })?;
        let id = conn.last_insert_rowid();
        conn.query_row("SELECT id,guild_id,feed_url,target_channel_id,message_template,mention,enabled,interval_seconds,last_item_id,next_poll_at,failure_count,last_error,created_by,created_at,updated_at FROM rss_subscriptions WHERE id=?1", [id], rss_subscription_from_row).map_err(Into::into)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn update_rss_subscription(
        &self,
        guild_id: &str,
        id: i64,
        feed_url: &str,
        target_channel_id: &str,
        message_template: &str,
        mention: &str,
        enabled: bool,
        interval_seconds: i64,
    ) -> Result<Option<RssSubscriptionRecord>> {
        let now = Utc::now().timestamp_millis();
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.execute("UPDATE rss_subscriptions SET feed_url=?3,target_channel_id=?4,message_template=?5,mention=?6,enabled=?7,interval_seconds=?8,updated_at=?9 WHERE guild_id=?1 AND id=?2", params![guild_id, id, feed_url, target_channel_id, message_template, mention, if enabled { 1_i64 } else { 0_i64 }, interval_seconds, now])?;
        conn.query_row("SELECT id,guild_id,feed_url,target_channel_id,message_template,mention,enabled,interval_seconds,last_item_id,next_poll_at,failure_count,last_error,created_by,created_at,updated_at FROM rss_subscriptions WHERE guild_id=?1 AND id=?2", params![guild_id, id], rss_subscription_from_row).optional()?.map_or(Ok(None), |record| Ok(Some(record)))
    }

    pub fn delete_rss_subscription(&self, guild_id: &str, id: i64) -> Result<bool> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        Ok(conn.execute(
            "DELETE FROM rss_subscriptions WHERE guild_id=?1 AND id=?2",
            params![guild_id, id],
        )? > 0)
    }

    pub fn due_rss_subscriptions(
        &self,
        now_ms: i64,
        limit: u32,
    ) -> Result<Vec<RssSubscriptionRecord>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let mut stmt = conn.prepare("SELECT id,guild_id,feed_url,target_channel_id,message_template,mention,enabled,interval_seconds,last_item_id,next_poll_at,failure_count,last_error,created_by,created_at,updated_at FROM rss_subscriptions WHERE enabled=1 AND next_poll_at<=?1 ORDER BY next_poll_at ASC LIMIT ?2")?;
        let rows = stmt.query_map(
            params![now_ms, i64::from(limit.min(100))],
            rss_subscription_from_row,
        )?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn update_rss_poll(
        &self,
        id: i64,
        last_item_id: Option<&str>,
        next_poll_at: i64,
        failure_count: i64,
        last_error: Option<&str>,
    ) -> Result<()> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.execute("UPDATE rss_subscriptions SET last_item_id=?2,next_poll_at=?3,failure_count=?4,last_error=?5,updated_at=?3 WHERE id=?1", params![id, last_item_id, next_poll_at, failure_count, last_error])?;
        Ok(())
    }

    pub fn bluesky_subscriptions(&self, guild_id: &str) -> Result<Vec<BlueskySubscriptionRecord>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let mut stmt = conn.prepare("SELECT id,guild_id,source_handle,target_channel_id,message_template,mention,enabled,interval_seconds,last_post_uri,next_poll_at,failure_count,last_error,created_by,created_at,updated_at FROM bluesky_subscriptions WHERE guild_id=?1 ORDER BY updated_at DESC, id DESC")?;
        let rows = stmt.query_map([guild_id], bluesky_subscription_from_row)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_bluesky_subscription(
        &self,
        guild_id: &str,
        source_handle: &str,
        target_channel_id: &str,
        message_template: &str,
        mention: &str,
        enabled: bool,
        interval_seconds: i64,
        created_by: &str,
    ) -> Result<BlueskySubscriptionRecord> {
        let now = Utc::now().timestamp_millis();
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.execute("INSERT INTO bluesky_subscriptions(guild_id,source_handle,target_channel_id,message_template,mention,enabled,interval_seconds,next_poll_at,created_by,created_at,updated_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?8,?8)", params![guild_id, source_handle, target_channel_id, message_template, mention, if enabled { 1_i64 } else { 0_i64 }, interval_seconds, now, created_by])
            .map_err(|error| if error.to_string().contains("UNIQUE") { anyhow!("bluesky_subscription_exists") } else { error.into() })?;
        let id = conn.last_insert_rowid();
        conn.query_row("SELECT id,guild_id,source_handle,target_channel_id,message_template,mention,enabled,interval_seconds,last_post_uri,next_poll_at,failure_count,last_error,created_by,created_at,updated_at FROM bluesky_subscriptions WHERE id=?1", [id], bluesky_subscription_from_row).map_err(Into::into)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn update_bluesky_subscription(
        &self,
        guild_id: &str,
        id: i64,
        source_handle: &str,
        target_channel_id: &str,
        message_template: &str,
        mention: &str,
        enabled: bool,
        interval_seconds: i64,
    ) -> Result<Option<BlueskySubscriptionRecord>> {
        let now = Utc::now().timestamp_millis();
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.execute("UPDATE bluesky_subscriptions SET source_handle=?3,target_channel_id=?4,message_template=?5,mention=?6,enabled=?7,interval_seconds=?8,updated_at=?9 WHERE guild_id=?1 AND id=?2", params![guild_id, id, source_handle, target_channel_id, message_template, mention, if enabled { 1_i64 } else { 0_i64 }, interval_seconds, now])?;
        conn.query_row("SELECT id,guild_id,source_handle,target_channel_id,message_template,mention,enabled,interval_seconds,last_post_uri,next_poll_at,failure_count,last_error,created_by,created_at,updated_at FROM bluesky_subscriptions WHERE guild_id=?1 AND id=?2", params![guild_id, id], bluesky_subscription_from_row).optional()?.map_or(Ok(None), |record| Ok(Some(record)))
    }

    pub fn delete_bluesky_subscription(&self, guild_id: &str, id: i64) -> Result<bool> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        Ok(conn.execute(
            "DELETE FROM bluesky_subscriptions WHERE guild_id=?1 AND id=?2",
            params![guild_id, id],
        )? > 0)
    }

    pub fn due_bluesky_subscriptions(
        &self,
        now_ms: i64,
        limit: u32,
    ) -> Result<Vec<BlueskySubscriptionRecord>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let mut stmt = conn.prepare("SELECT id,guild_id,source_handle,target_channel_id,message_template,mention,enabled,interval_seconds,last_post_uri,next_poll_at,failure_count,last_error,created_by,created_at,updated_at FROM bluesky_subscriptions WHERE enabled=1 AND next_poll_at<=?1 ORDER BY next_poll_at ASC LIMIT ?2")?;
        let rows = stmt.query_map(
            params![now_ms, i64::from(limit.min(100))],
            bluesky_subscription_from_row,
        )?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn update_bluesky_poll(
        &self,
        id: i64,
        last_post_uri: Option<&str>,
        next_poll_at: i64,
        failure_count: i64,
        last_error: Option<&str>,
    ) -> Result<()> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.execute("UPDATE bluesky_subscriptions SET last_post_uri=?2,next_poll_at=?3,failure_count=?4,last_error=?5,updated_at=?3 WHERE id=?1", params![id, last_post_uri, next_poll_at, failure_count, last_error])?;
        Ok(())
    }

    pub fn reddit_subscriptions(&self, guild_id: &str) -> Result<Vec<RedditSubscriptionRecord>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let mut stmt = conn.prepare("SELECT id,guild_id,source_subreddit,target_channel_id,message_template,mention,enabled,interval_seconds,last_post_id,next_poll_at,failure_count,last_error,created_by,created_at,updated_at FROM reddit_subscriptions WHERE guild_id=?1 ORDER BY updated_at DESC, id DESC")?;
        let rows = stmt.query_map([guild_id], reddit_subscription_from_row)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_reddit_subscription(
        &self,
        guild_id: &str,
        source_subreddit: &str,
        target_channel_id: &str,
        message_template: &str,
        mention: &str,
        enabled: bool,
        interval_seconds: i64,
        created_by: &str,
    ) -> Result<RedditSubscriptionRecord> {
        let now = Utc::now().timestamp_millis();
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.execute("INSERT INTO reddit_subscriptions(guild_id,source_subreddit,target_channel_id,message_template,mention,enabled,interval_seconds,next_poll_at,created_by,created_at,updated_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?8,?8)", params![guild_id, source_subreddit, target_channel_id, message_template, mention, if enabled { 1_i64 } else { 0_i64 }, interval_seconds, now, created_by])
            .map_err(|error| if error.to_string().contains("UNIQUE") { anyhow!("reddit_subscription_exists") } else { error.into() })?;
        let id = conn.last_insert_rowid();
        conn.query_row("SELECT id,guild_id,source_subreddit,target_channel_id,message_template,mention,enabled,interval_seconds,last_post_id,next_poll_at,failure_count,last_error,created_by,created_at,updated_at FROM reddit_subscriptions WHERE id=?1", [id], reddit_subscription_from_row).map_err(Into::into)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn update_reddit_subscription(
        &self,
        guild_id: &str,
        id: i64,
        source_subreddit: &str,
        target_channel_id: &str,
        message_template: &str,
        mention: &str,
        enabled: bool,
        interval_seconds: i64,
    ) -> Result<Option<RedditSubscriptionRecord>> {
        let now = Utc::now().timestamp_millis();
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.execute("UPDATE reddit_subscriptions SET source_subreddit=?3,target_channel_id=?4,message_template=?5,mention=?6,enabled=?7,interval_seconds=?8,last_post_id=NULL,next_poll_at=?9,failure_count=0,last_error=NULL,updated_at=?9 WHERE guild_id=?1 AND id=?2", params![guild_id, id, source_subreddit, target_channel_id, message_template, mention, if enabled { 1_i64 } else { 0_i64 }, interval_seconds, now])?;
        conn.query_row("SELECT id,guild_id,source_subreddit,target_channel_id,message_template,mention,enabled,interval_seconds,last_post_id,next_poll_at,failure_count,last_error,created_by,created_at,updated_at FROM reddit_subscriptions WHERE guild_id=?1 AND id=?2", params![guild_id, id], reddit_subscription_from_row).optional()?.map_or(Ok(None), |record| Ok(Some(record)))
    }

    pub fn delete_reddit_subscription(&self, guild_id: &str, id: i64) -> Result<bool> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        Ok(conn.execute(
            "DELETE FROM reddit_subscriptions WHERE guild_id=?1 AND id=?2",
            params![guild_id, id],
        )? > 0)
    }

    pub fn due_reddit_subscriptions(
        &self,
        now_ms: i64,
        limit: u32,
    ) -> Result<Vec<RedditSubscriptionRecord>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let mut stmt = conn.prepare("SELECT id,guild_id,source_subreddit,target_channel_id,message_template,mention,enabled,interval_seconds,last_post_id,next_poll_at,failure_count,last_error,created_by,created_at,updated_at FROM reddit_subscriptions WHERE enabled=1 AND next_poll_at<=?1 ORDER BY next_poll_at ASC LIMIT ?2")?;
        let rows = stmt.query_map(
            params![now_ms, i64::from(limit.min(100))],
            reddit_subscription_from_row,
        )?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn update_reddit_poll(
        &self,
        id: i64,
        last_post_id: Option<&str>,
        next_poll_at: i64,
        failure_count: i64,
        last_error: Option<&str>,
    ) -> Result<()> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.execute("UPDATE reddit_subscriptions SET last_post_id=?2,next_poll_at=?3,failure_count=?4,last_error=?5,updated_at=?3 WHERE id=?1", params![id, last_post_id, next_poll_at, failure_count, last_error])?;
        Ok(())
    }

    pub fn x_subscriptions(&self, guild_id: &str) -> Result<Vec<XSubscriptionRecord>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let mut stmt = conn.prepare("SELECT id,guild_id,source_handle,target_channel_id,message_template,mention,enabled,interval_seconds,last_post_id,next_poll_at,failure_count,last_error,created_by,created_at,updated_at FROM x_subscriptions WHERE guild_id=?1 ORDER BY updated_at DESC, id DESC")?;
        let rows = stmt.query_map([guild_id], x_subscription_from_row)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_x_subscription(
        &self,
        guild_id: &str,
        source_handle: &str,
        target_channel_id: &str,
        message_template: &str,
        mention: &str,
        enabled: bool,
        interval_seconds: i64,
        created_by: &str,
    ) -> Result<XSubscriptionRecord> {
        let now = Utc::now().timestamp_millis();
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.execute("INSERT INTO x_subscriptions(guild_id,source_handle,target_channel_id,message_template,mention,enabled,interval_seconds,next_poll_at,created_by,created_at,updated_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?8,?8)", params![guild_id, source_handle, target_channel_id, message_template, mention, if enabled { 1_i64 } else { 0_i64 }, interval_seconds, now, created_by])
            .map_err(|error| if error.to_string().contains("UNIQUE") { anyhow!("x_subscription_exists") } else { error.into() })?;
        let id = conn.last_insert_rowid();
        conn.query_row("SELECT id,guild_id,source_handle,target_channel_id,message_template,mention,enabled,interval_seconds,last_post_id,next_poll_at,failure_count,last_error,created_by,created_at,updated_at FROM x_subscriptions WHERE id=?1", [id], x_subscription_from_row).map_err(Into::into)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn update_x_subscription(
        &self,
        guild_id: &str,
        id: i64,
        source_handle: &str,
        target_channel_id: &str,
        message_template: &str,
        mention: &str,
        enabled: bool,
        interval_seconds: i64,
    ) -> Result<Option<XSubscriptionRecord>> {
        let now = Utc::now().timestamp_millis();
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.execute("UPDATE x_subscriptions SET source_handle=?3,target_channel_id=?4,message_template=?5,mention=?6,enabled=?7,interval_seconds=?8,last_post_id=NULL,next_poll_at=?9,failure_count=0,last_error=NULL,updated_at=?9 WHERE guild_id=?1 AND id=?2", params![guild_id, id, source_handle, target_channel_id, message_template, mention, if enabled { 1_i64 } else { 0_i64 }, interval_seconds, now])?;
        conn.query_row("SELECT id,guild_id,source_handle,target_channel_id,message_template,mention,enabled,interval_seconds,last_post_id,next_poll_at,failure_count,last_error,created_by,created_at,updated_at FROM x_subscriptions WHERE guild_id=?1 AND id=?2", params![guild_id, id], x_subscription_from_row).optional()?.map_or(Ok(None), |record| Ok(Some(record)))
    }

    pub fn delete_x_subscription(&self, guild_id: &str, id: i64) -> Result<bool> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        Ok(conn.execute(
            "DELETE FROM x_subscriptions WHERE guild_id=?1 AND id=?2",
            params![guild_id, id],
        )? > 0)
    }

    pub fn due_x_subscriptions(&self, now_ms: i64, limit: u32) -> Result<Vec<XSubscriptionRecord>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let mut stmt = conn.prepare("SELECT id,guild_id,source_handle,target_channel_id,message_template,mention,enabled,interval_seconds,last_post_id,next_poll_at,failure_count,last_error,created_by,created_at,updated_at FROM x_subscriptions WHERE enabled=1 AND next_poll_at<=?1 ORDER BY next_poll_at ASC LIMIT ?2")?;
        let rows = stmt.query_map(
            params![now_ms, i64::from(limit.min(100))],
            x_subscription_from_row,
        )?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn update_x_poll(
        &self,
        id: i64,
        last_post_id: Option<&str>,
        next_poll_at: i64,
        failure_count: i64,
        last_error: Option<&str>,
    ) -> Result<()> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.execute("UPDATE x_subscriptions SET last_post_id=?2,next_poll_at=?3,failure_count=?4,last_error=?5,updated_at=?3 WHERE id=?1", params![id, last_post_id, next_poll_at, failure_count, last_error])?;
        Ok(())
    }

    pub fn tiktok_subscriptions(&self, guild_id: &str) -> Result<Vec<TikTokSubscriptionRecord>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let mut stmt = conn.prepare("SELECT id,guild_id,source_label,target_channel_id,message_template,mention,enabled,interval_seconds,last_video_id,next_poll_at,failure_count,last_error,created_by,created_at,updated_at FROM tiktok_subscriptions WHERE guild_id=?1 ORDER BY updated_at DESC, id DESC")?;
        let rows = stmt.query_map([guild_id], tiktok_subscription_from_row)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn save_tiktok_grant(
        &self,
        guild_id: &str,
        open_id: &str,
        display_name: &str,
        access_token_sealed: &str,
        refresh_token_sealed: &str,
        scopes: &str,
        access_expires_at: i64,
        refresh_expires_at: i64,
        updated_at: i64,
    ) -> Result<()> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.execute(
            "INSERT INTO tiktok_grants(guild_id,open_id,display_name,access_token_sealed,refresh_token_sealed,scopes,access_expires_at,refresh_expires_at,updated_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9) ON CONFLICT(guild_id) DO UPDATE SET open_id=excluded.open_id,display_name=excluded.display_name,access_token_sealed=excluded.access_token_sealed,refresh_token_sealed=excluded.refresh_token_sealed,scopes=excluded.scopes,access_expires_at=excluded.access_expires_at,refresh_expires_at=excluded.refresh_expires_at,updated_at=excluded.updated_at",
            params![guild_id, open_id, display_name, access_token_sealed, refresh_token_sealed, scopes, access_expires_at, refresh_expires_at, updated_at],
        )?;
        Ok(())
    }

    pub fn tiktok_grant(&self, guild_id: &str) -> Result<Option<TikTokGrantRecord>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.query_row(
            "SELECT guild_id,open_id,display_name,access_token_sealed,refresh_token_sealed,scopes,access_expires_at,refresh_expires_at,updated_at FROM tiktok_grants WHERE guild_id=?1",
            [guild_id],
            |row| Ok(TikTokGrantRecord {
                guild_id: row.get(0)?, open_id: row.get(1)?, display_name: row.get(2)?,
                access_token_sealed: row.get(3)?, refresh_token_sealed: row.get(4)?, scopes: row.get(5)?,
                access_expires_at: row.get(6)?, refresh_expires_at: row.get(7)?, updated_at: row.get(8)?,
            }),
        ).optional().map_err(Into::into)
    }

    pub fn delete_tiktok_grant(&self, guild_id: &str) -> Result<bool> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        Ok(conn.execute("DELETE FROM tiktok_grants WHERE guild_id=?1", [guild_id])? > 0)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_tiktok_subscription(
        &self,
        guild_id: &str,
        source_label: &str,
        target_channel_id: &str,
        message_template: &str,
        mention: &str,
        enabled: bool,
        interval_seconds: i64,
        created_by: &str,
    ) -> Result<TikTokSubscriptionRecord> {
        let now = Utc::now().timestamp_millis();
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.execute("INSERT INTO tiktok_subscriptions(guild_id,source_label,target_channel_id,message_template,mention,enabled,interval_seconds,next_poll_at,created_by,created_at,updated_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?8,?8)", params![guild_id, source_label, target_channel_id, message_template, mention, if enabled { 1_i64 } else { 0_i64 }, interval_seconds, now, created_by])
            .map_err(|error| if error.to_string().contains("UNIQUE") { anyhow!("tiktok_subscription_exists") } else { error.into() })?;
        let id = conn.last_insert_rowid();
        conn.query_row("SELECT id,guild_id,source_label,target_channel_id,message_template,mention,enabled,interval_seconds,last_video_id,next_poll_at,failure_count,last_error,created_by,created_at,updated_at FROM tiktok_subscriptions WHERE id=?1", [id], tiktok_subscription_from_row).map_err(Into::into)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn update_tiktok_subscription(
        &self,
        guild_id: &str,
        id: i64,
        source_label: &str,
        target_channel_id: &str,
        message_template: &str,
        mention: &str,
        enabled: bool,
        interval_seconds: i64,
    ) -> Result<Option<TikTokSubscriptionRecord>> {
        let now = Utc::now().timestamp_millis();
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.execute("UPDATE tiktok_subscriptions SET source_label=?3,target_channel_id=?4,message_template=?5,mention=?6,enabled=?7,interval_seconds=?8,last_video_id=NULL,next_poll_at=?9,failure_count=0,last_error=NULL,updated_at=?9 WHERE guild_id=?1 AND id=?2", params![guild_id, id, source_label, target_channel_id, message_template, mention, if enabled { 1_i64 } else { 0_i64 }, interval_seconds, now])?;
        conn.query_row("SELECT id,guild_id,source_label,target_channel_id,message_template,mention,enabled,interval_seconds,last_video_id,next_poll_at,failure_count,last_error,created_by,created_at,updated_at FROM tiktok_subscriptions WHERE guild_id=?1 AND id=?2", params![guild_id, id], tiktok_subscription_from_row).optional()?.map_or(Ok(None), |record| Ok(Some(record)))
    }

    pub fn delete_tiktok_subscription(&self, guild_id: &str, id: i64) -> Result<bool> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        Ok(conn.execute(
            "DELETE FROM tiktok_subscriptions WHERE guild_id=?1 AND id=?2",
            params![guild_id, id],
        )? > 0)
    }

    pub fn due_tiktok_subscriptions(
        &self,
        now_ms: i64,
        limit: u32,
    ) -> Result<Vec<TikTokSubscriptionRecord>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let mut stmt = conn.prepare("SELECT id,guild_id,source_label,target_channel_id,message_template,mention,enabled,interval_seconds,last_video_id,next_poll_at,failure_count,last_error,created_by,created_at,updated_at FROM tiktok_subscriptions WHERE enabled=1 AND next_poll_at<=?1 ORDER BY next_poll_at ASC LIMIT ?2")?;
        let rows = stmt.query_map(
            params![now_ms, i64::from(limit.min(100))],
            tiktok_subscription_from_row,
        )?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn update_tiktok_poll(
        &self,
        id: i64,
        last_video_id: Option<&str>,
        next_poll_at: i64,
        failure_count: i64,
        last_error: Option<&str>,
    ) -> Result<()> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.execute("UPDATE tiktok_subscriptions SET last_video_id=?2,next_poll_at=?3,failure_count=?4,last_error=?5,updated_at=?3 WHERE id=?1", params![id, last_video_id, next_poll_at, failure_count, last_error])?;
        Ok(())
    }

    pub fn instagram_subscriptions(
        &self,
        guild_id: &str,
    ) -> Result<Vec<InstagramSubscriptionRecord>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let mut stmt = conn.prepare("SELECT id,guild_id,source_label,target_channel_id,message_template,mention,enabled,interval_seconds,last_media_id,next_poll_at,failure_count,last_error,created_by,created_at,updated_at FROM instagram_subscriptions WHERE guild_id=?1 ORDER BY updated_at DESC,id DESC")?;
        let rows = stmt.query_map([guild_id], instagram_subscription_from_row)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_instagram_subscription(
        &self,
        guild_id: &str,
        source_label: &str,
        target_channel_id: &str,
        message_template: &str,
        mention: &str,
        enabled: bool,
        interval_seconds: i64,
        created_by: &str,
    ) -> Result<InstagramSubscriptionRecord> {
        let now = Utc::now().timestamp_millis();
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.execute("INSERT INTO instagram_subscriptions(guild_id,source_label,target_channel_id,message_template,mention,enabled,interval_seconds,next_poll_at,created_by,created_at,updated_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?8,?8)", params![guild_id,source_label,target_channel_id,message_template,mention,if enabled {1_i64}else{0_i64},interval_seconds,now,created_by]).map_err(|error|if error.to_string().contains("UNIQUE"){anyhow!("instagram_subscription_exists")}else{error.into()})?;
        let id = conn.last_insert_rowid();
        conn.query_row("SELECT id,guild_id,source_label,target_channel_id,message_template,mention,enabled,interval_seconds,last_media_id,next_poll_at,failure_count,last_error,created_by,created_at,updated_at FROM instagram_subscriptions WHERE id=?1", [id], instagram_subscription_from_row).map_err(Into::into)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn update_instagram_subscription(
        &self,
        guild_id: &str,
        id: i64,
        source_label: &str,
        target_channel_id: &str,
        message_template: &str,
        mention: &str,
        enabled: bool,
        interval_seconds: i64,
    ) -> Result<Option<InstagramSubscriptionRecord>> {
        let now = Utc::now().timestamp_millis();
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.execute("UPDATE instagram_subscriptions SET source_label=?3,target_channel_id=?4,message_template=?5,mention=?6,enabled=?7,interval_seconds=?8,last_media_id=NULL,next_poll_at=?9,failure_count=0,last_error=NULL,updated_at=?9 WHERE guild_id=?1 AND id=?2", params![guild_id,id,source_label,target_channel_id,message_template,mention,if enabled {1_i64}else{0_i64},interval_seconds,now])?;
        conn.query_row("SELECT id,guild_id,source_label,target_channel_id,message_template,mention,enabled,interval_seconds,last_media_id,next_poll_at,failure_count,last_error,created_by,created_at,updated_at FROM instagram_subscriptions WHERE guild_id=?1 AND id=?2", params![guild_id,id], instagram_subscription_from_row).optional()?.map_or(Ok(None),|record|Ok(Some(record)))
    }

    pub fn delete_instagram_subscription(&self, guild_id: &str, id: i64) -> Result<bool> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        Ok(conn.execute(
            "DELETE FROM instagram_subscriptions WHERE guild_id=?1 AND id=?2",
            params![guild_id, id],
        )? > 0)
    }
    pub fn due_instagram_subscriptions(
        &self,
        now_ms: i64,
        limit: u32,
    ) -> Result<Vec<InstagramSubscriptionRecord>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let mut stmt=conn.prepare("SELECT id,guild_id,source_label,target_channel_id,message_template,mention,enabled,interval_seconds,last_media_id,next_poll_at,failure_count,last_error,created_by,created_at,updated_at FROM instagram_subscriptions WHERE enabled=1 AND next_poll_at<=?1 ORDER BY next_poll_at ASC LIMIT ?2")?;
        let rows = stmt.query_map(
            params![now_ms, i64::from(limit.min(100))],
            instagram_subscription_from_row,
        )?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }
    pub fn update_instagram_poll(
        &self,
        id: i64,
        last_media_id: Option<&str>,
        next_poll_at: i64,
        failure_count: i64,
        last_error: Option<&str>,
    ) -> Result<()> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.execute("UPDATE instagram_subscriptions SET last_media_id=?2,next_poll_at=?3,failure_count=?4,last_error=?5,updated_at=?3 WHERE id=?1",params![id,last_media_id,next_poll_at,failure_count,last_error])?;
        Ok(())
    }

    pub fn kick_subscriptions(&self, guild_id: &str) -> Result<Vec<KickSubscriptionRecord>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let mut stmt=conn.prepare("SELECT id,guild_id,source_handle,target_channel_id,message_template,mention,enabled,interval_seconds,last_stream_id,next_poll_at,failure_count,last_error,created_by,created_at,updated_at FROM kick_subscriptions WHERE guild_id=?1 ORDER BY updated_at DESC,id DESC")?;
        let rows = stmt.query_map([guild_id], kick_subscription_from_row)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }
    #[allow(clippy::too_many_arguments)]
    pub fn create_kick_subscription(
        &self,
        guild_id: &str,
        source_handle: &str,
        target_channel_id: &str,
        message_template: &str,
        mention: &str,
        enabled: bool,
        interval_seconds: i64,
        created_by: &str,
    ) -> Result<KickSubscriptionRecord> {
        let now = Utc::now().timestamp_millis();
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.execute("INSERT INTO kick_subscriptions(guild_id,source_handle,target_channel_id,message_template,mention,enabled,interval_seconds,next_poll_at,created_by,created_at,updated_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?8,?8)",params![guild_id,source_handle,target_channel_id,message_template,mention,if enabled {1_i64}else{0_i64},interval_seconds,now,created_by]).map_err(|error|if error.to_string().contains("UNIQUE"){anyhow!("kick_subscription_exists")}else{error.into()})?;
        let id = conn.last_insert_rowid();
        conn.query_row("SELECT id,guild_id,source_handle,target_channel_id,message_template,mention,enabled,interval_seconds,last_stream_id,next_poll_at,failure_count,last_error,created_by,created_at,updated_at FROM kick_subscriptions WHERE id=?1",[id],kick_subscription_from_row).map_err(Into::into)
    }
    #[allow(clippy::too_many_arguments)]
    pub fn update_kick_subscription(
        &self,
        guild_id: &str,
        id: i64,
        source_handle: &str,
        target_channel_id: &str,
        message_template: &str,
        mention: &str,
        enabled: bool,
        interval_seconds: i64,
    ) -> Result<Option<KickSubscriptionRecord>> {
        let now = Utc::now().timestamp_millis();
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.execute("UPDATE kick_subscriptions SET source_handle=?3,target_channel_id=?4,message_template=?5,mention=?6,enabled=?7,interval_seconds=?8,last_stream_id=NULL,next_poll_at=?9,failure_count=0,last_error=NULL,updated_at=?9 WHERE guild_id=?1 AND id=?2",params![guild_id,id,source_handle,target_channel_id,message_template,mention,if enabled {1_i64}else{0_i64},interval_seconds,now])?;
        conn.query_row("SELECT id,guild_id,source_handle,target_channel_id,message_template,mention,enabled,interval_seconds,last_stream_id,next_poll_at,failure_count,last_error,created_by,created_at,updated_at FROM kick_subscriptions WHERE guild_id=?1 AND id=?2",params![guild_id,id],kick_subscription_from_row).optional()?.map_or(Ok(None),|record|Ok(Some(record)))
    }
    pub fn delete_kick_subscription(&self, guild_id: &str, id: i64) -> Result<bool> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        Ok(conn.execute(
            "DELETE FROM kick_subscriptions WHERE guild_id=?1 AND id=?2",
            params![guild_id, id],
        )? > 0)
    }
    pub fn due_kick_subscriptions(
        &self,
        now_ms: i64,
        limit: u32,
    ) -> Result<Vec<KickSubscriptionRecord>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let mut stmt=conn.prepare("SELECT id,guild_id,source_handle,target_channel_id,message_template,mention,enabled,interval_seconds,last_stream_id,next_poll_at,failure_count,last_error,created_by,created_at,updated_at FROM kick_subscriptions WHERE enabled=1 AND next_poll_at<=?1 ORDER BY next_poll_at ASC LIMIT ?2")?;
        let rows = stmt.query_map(
            params![now_ms, i64::from(limit.min(100))],
            kick_subscription_from_row,
        )?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }
    pub fn update_kick_poll(
        &self,
        id: i64,
        last_stream_id: Option<&str>,
        next_poll_at: i64,
        failure_count: i64,
        last_error: Option<&str>,
    ) -> Result<()> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.execute("UPDATE kick_subscriptions SET last_stream_id=?2,next_poll_at=?3,failure_count=?4,last_error=?5,updated_at=?3 WHERE id=?1",params![id,last_stream_id,next_poll_at,failure_count,last_error])?;
        Ok(())
    }

    /// Publishes Instagram configuration and its authorised-account
    /// subscription atomically with the feature revision and audit event.
    #[allow(clippy::too_many_arguments)]
    pub fn publish_instagram_feature_setting(
        &self,
        guild_id: &str,
        key: &str,
        enabled: bool,
        config_json: &str,
        expected_revision: Option<u64>,
        updated_by: &str,
        projections: &[(String, String)],
        subscription: Option<&InstagramSubscriptionWrite>,
    ) -> Result<FeatureSettingRecord> {
        let mut conn = self.conn.lock().expect("store mutex poisoned");
        let tx = conn.transaction()?;
        let record = Self::publish_instagram_feature_setting_on_tx(
            &tx,
            guild_id,
            key,
            enabled,
            config_json,
            expected_revision,
            updated_by,
            projections,
            subscription,
        )?;
        tx.commit()?;
        Ok(record)
    }

    #[allow(clippy::too_many_arguments)]
    fn publish_instagram_feature_setting_on_tx(
        tx: &rusqlite::Transaction<'_>,
        guild_id: &str,
        key: &str,
        enabled: bool,
        config_json: &str,
        expected_revision: Option<u64>,
        updated_by: &str,
        projections: &[(String, String)],
        subscription: Option<&InstagramSubscriptionWrite>,
    ) -> Result<FeatureSettingRecord> {
        let current: Option<(i64, i64, String)> = tx.query_row(
            "SELECT revision,enabled,config_json FROM feature_settings WHERE guild_id=?1 AND key=?2",
            params![guild_id, key], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        ).optional()?;
        let current_revision = current
            .as_ref()
            .and_then(|item| u64::try_from(item.0).ok())
            .unwrap_or(0);
        if expected_revision.is_some_and(|value| value != current_revision) {
            bail!("feature_revision_conflict:{current_revision}");
        }
        let next_revision = current_revision.saturating_add(1);
        let now = Utc::now().timestamp_millis();
        tx.execute("INSERT INTO feature_settings(guild_id,key,enabled,config_json,revision,updated_at,updated_by) VALUES(?1,?2,?3,?4,?5,?6,?7) ON CONFLICT(guild_id,key) DO UPDATE SET enabled=excluded.enabled,config_json=excluded.config_json,revision=excluded.revision,updated_at=excluded.updated_at,updated_by=excluded.updated_by", params![guild_id,key,if enabled {1_i64}else{0_i64},config_json,i64::try_from(next_revision).unwrap_or(i64::MAX),now,updated_by])?;
        tx.execute("INSERT INTO feature_revisions(guild_id,key,revision,enabled,config_json,updated_at,updated_by) VALUES(?1,?2,?3,?4,?5,?6,?7)", params![guild_id,key,i64::try_from(next_revision).unwrap_or(i64::MAX),if enabled {1_i64}else{0_i64},config_json,now,updated_by])?;
        for (projection_key, projection_value) in projections {
            tx.execute("INSERT INTO settings(guild_id,key,value,updated_at) VALUES(?1,?2,?3,?4) ON CONFLICT(guild_id,key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at", params![guild_id,projection_key,projection_value,now])?;
        }
        if let Some(subscription) = subscription {
            let existing_id: Option<i64> = tx.query_row("SELECT id FROM instagram_subscriptions WHERE guild_id=?1 ORDER BY updated_at DESC,id DESC LIMIT 1", [guild_id], |row| row.get(0)).optional()?;
            if let Some(id) = existing_id {
                tx.execute("UPDATE instagram_subscriptions SET source_label=?2,target_channel_id=?3,message_template=?4,mention=?5,enabled=?6,interval_seconds=?7,last_media_id=NULL,next_poll_at=?8,failure_count=0,last_error=NULL,updated_at=?8 WHERE guild_id=?1 AND id=?9", params![guild_id,subscription.source_label,subscription.target_channel_id,subscription.message_template,subscription.mention,if subscription.enabled {1_i64}else{0_i64},subscription.interval_seconds,now,id])?;
            } else if subscription.enabled {
                tx.execute("INSERT INTO instagram_subscriptions(guild_id,source_label,target_channel_id,message_template,mention,enabled,interval_seconds,next_poll_at,created_by,created_at,updated_at) VALUES(?1,?2,?3,?4,?5,1,?6,?7,?8,?7,?7)", params![guild_id,subscription.source_label,subscription.target_channel_id,subscription.message_template,subscription.mention,subscription.interval_seconds,now,subscription.created_by])?;
            }
        } else if !enabled {
            tx.execute(
                "UPDATE instagram_subscriptions SET enabled=0,updated_at=?2 WHERE guild_id=?1",
                params![guild_id, now],
            )?;
        }
        let correlation_id = Uuid::new_v4().to_string();
        let before_json = current
            .as_ref()
            .map(
                |item| serde_json::json!({"enabled":item.1 != 0,"config":item.2,"revision":item.0}),
            )
            .unwrap_or_else(|| serde_json::json!({}));
        let after_json = serde_json::json!({"enabled":enabled,"config":serde_json::from_str::<serde_json::Value>(config_json).unwrap_or_else(|_| serde_json::json!({})),"revision":next_revision});
        tx.execute("INSERT INTO audit_events(correlation_id,guild_id,actor_id,action,reason,before_json,after_json,outcome,created_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)", params![correlation_id,guild_id,updated_by,"feature.publish",key,before_json.to_string(),after_json.to_string(),"published",now])?;
        Ok(FeatureSettingRecord {
            guild_id: guild_id.to_string(),
            key: key.to_string(),
            enabled,
            config_json: config_json.to_string(),
            revision: next_revision,
            updated_at: now,
            updated_by: updated_by.to_string(),
        })
    }

    /// Publishes Kick configuration and its channel subscription atomically.
    #[allow(clippy::too_many_arguments)]
    pub fn publish_kick_feature_setting(
        &self,
        guild_id: &str,
        key: &str,
        enabled: bool,
        config_json: &str,
        expected_revision: Option<u64>,
        updated_by: &str,
        projections: &[(String, String)],
        subscription: Option<&KickSubscriptionWrite>,
    ) -> Result<FeatureSettingRecord> {
        let mut conn = self.conn.lock().expect("store mutex poisoned");
        let tx = conn.transaction()?;
        let record = Self::publish_kick_feature_setting_on_tx(
            &tx,
            guild_id,
            key,
            enabled,
            config_json,
            expected_revision,
            updated_by,
            projections,
            subscription,
        )?;
        tx.commit()?;
        Ok(record)
    }

    #[allow(clippy::too_many_arguments)]
    fn publish_kick_feature_setting_on_tx(
        tx: &rusqlite::Transaction<'_>,
        guild_id: &str,
        key: &str,
        enabled: bool,
        config_json: &str,
        expected_revision: Option<u64>,
        updated_by: &str,
        projections: &[(String, String)],
        subscription: Option<&KickSubscriptionWrite>,
    ) -> Result<FeatureSettingRecord> {
        let current: Option<(i64,i64,String)> = tx.query_row("SELECT revision,enabled,config_json FROM feature_settings WHERE guild_id=?1 AND key=?2", params![guild_id,key], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?))).optional()?;
        let current_revision = current
            .as_ref()
            .and_then(|item| u64::try_from(item.0).ok())
            .unwrap_or(0);
        if expected_revision.is_some_and(|value| value != current_revision) {
            bail!("feature_revision_conflict:{current_revision}");
        }
        let next_revision = current_revision.saturating_add(1);
        let now = Utc::now().timestamp_millis();
        tx.execute("INSERT INTO feature_settings(guild_id,key,enabled,config_json,revision,updated_at,updated_by) VALUES(?1,?2,?3,?4,?5,?6,?7) ON CONFLICT(guild_id,key) DO UPDATE SET enabled=excluded.enabled,config_json=excluded.config_json,revision=excluded.revision,updated_at=excluded.updated_at,updated_by=excluded.updated_by", params![guild_id,key,if enabled {1_i64}else{0_i64},config_json,i64::try_from(next_revision).unwrap_or(i64::MAX),now,updated_by])?;
        tx.execute("INSERT INTO feature_revisions(guild_id,key,revision,enabled,config_json,updated_at,updated_by) VALUES(?1,?2,?3,?4,?5,?6,?7)", params![guild_id,key,i64::try_from(next_revision).unwrap_or(i64::MAX),if enabled {1_i64}else{0_i64},config_json,now,updated_by])?;
        for (projection_key, projection_value) in projections {
            tx.execute("INSERT INTO settings(guild_id,key,value,updated_at) VALUES(?1,?2,?3,?4) ON CONFLICT(guild_id,key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at", params![guild_id,projection_key,projection_value,now])?;
        }
        if let Some(subscription) = subscription {
            let existing_id:Option<i64>=tx.query_row("SELECT id FROM kick_subscriptions WHERE guild_id=?1 ORDER BY updated_at DESC,id DESC LIMIT 1", [guild_id], |row|row.get(0)).optional()?;
            if let Some(id) = existing_id {
                tx.execute("UPDATE kick_subscriptions SET source_handle=?2,target_channel_id=?3,message_template=?4,mention=?5,enabled=?6,interval_seconds=?7,last_stream_id=NULL,next_poll_at=?8,failure_count=0,last_error=NULL,updated_at=?8 WHERE guild_id=?1 AND id=?9", params![guild_id,subscription.source_handle,subscription.target_channel_id,subscription.message_template,subscription.mention,if subscription.enabled {1_i64}else{0_i64},subscription.interval_seconds,now,id])?;
            } else if subscription.enabled {
                tx.execute("INSERT INTO kick_subscriptions(guild_id,source_handle,target_channel_id,message_template,mention,enabled,interval_seconds,next_poll_at,created_by,created_at,updated_at) VALUES(?1,?2,?3,?4,?5,1,?6,?7,?8,?7,?7)", params![guild_id,subscription.source_handle,subscription.target_channel_id,subscription.message_template,subscription.mention,subscription.interval_seconds,now,subscription.created_by])?;
            }
        } else if !enabled {
            tx.execute(
                "UPDATE kick_subscriptions SET enabled=0,updated_at=?2 WHERE guild_id=?1",
                params![guild_id, now],
            )?;
        }
        let correlation_id = Uuid::new_v4().to_string();
        let before_json = current
            .as_ref()
            .map(|item| serde_json::json!({"enabled":item.1!=0,"config":item.2,"revision":item.0}))
            .unwrap_or_else(|| serde_json::json!({}));
        let after_json = serde_json::json!({"enabled":enabled,"config":serde_json::from_str::<serde_json::Value>(config_json).unwrap_or_else(|_|serde_json::json!({})),"revision":next_revision});
        tx.execute("INSERT INTO audit_events(correlation_id,guild_id,actor_id,action,reason,before_json,after_json,outcome,created_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)", params![correlation_id,guild_id,updated_by,"feature.publish",key,before_json.to_string(),after_json.to_string(),"published",now])?;
        Ok(FeatureSettingRecord {
            guild_id: guild_id.to_string(),
            key: key.to_string(),
            enabled,
            config_json: config_json.to_string(),
            revision: next_revision,
            updated_at: now,
            updated_by: updated_by.to_string(),
        })
    }

    pub fn set_setting(&self, guild_id: &str, key: &str, value: &str) -> Result<()> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.execute("INSERT INTO settings(guild_id,key,value,updated_at) VALUES(?1,?2,?3,?4) ON CONFLICT(guild_id,key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at", params![guild_id, key, value, Utc::now().timestamp_millis()])?;
        Ok(())
    }

    /// Arms the temporary anti-raid containment gate. The original manual
    /// gate state is captured only once, so repeated bursts can extend the
    /// deadline without accidentally making the temporary gate permanent.
    pub fn arm_anti_raid_latch(&self, guild_id: &str, gate_until: i64) -> Result<()> {
        let mut conn = self.conn.lock().expect("store mutex poisoned");
        let tx = conn.transaction()?;
        let latch_active: Option<String> = tx
            .query_row(
                "SELECT value FROM settings WHERE guild_id=?1 AND key='security.anti_raid.latch_active'",
                [guild_id],
                |row| row.get(0),
            )
            .optional()?;
        let now = Utc::now().timestamp_millis();
        if latch_active.as_deref() != Some("true") {
            let gate_enabled: Option<String> = tx
                .query_row(
                    "SELECT value FROM settings WHERE guild_id=?1 AND key='security.join_gate.enabled'",
                    [guild_id],
                    |row| row.get(0),
                )
                .optional()?;
            let previous_gate = gate_enabled
                .as_deref()
                .and_then(|value| value.parse::<bool>().ok())
                .unwrap_or(false);
            tx.execute(
                "INSERT INTO settings(guild_id,key,value,updated_at) VALUES(?1,'security.anti_raid.previous_gate_enabled',?2,?3) ON CONFLICT(guild_id,key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at",
                params![guild_id, previous_gate.to_string(), now],
            )?;
        }
        for (key, value) in [
            ("security.join_gate.enabled", "true".to_string()),
            ("security.anti_raid.gate_until", gate_until.to_string()),
            ("security.anti_raid.latch_active", "true".to_string()),
        ] {
            tx.execute(
                "INSERT INTO settings(guild_id,key,value,updated_at) VALUES(?1,?2,?3,?4) ON CONFLICT(guild_id,key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at",
                params![guild_id, key, value, now],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Returns guilds with an active anti-raid latch. This is deliberately
    /// independent of the feature toggle, because a stale latch must be
    /// restored even after an administrator turns anti-raid off.
    pub fn active_anti_raid_latch_guilds(&self, limit: usize) -> Result<Vec<String>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let conn = self.conn.lock().expect("store mutex poisoned");
        let mut statement = conn.prepare(
            "SELECT guild_id FROM settings WHERE key='security.anti_raid.latch_active' AND value='true' ORDER BY updated_at ASC LIMIT ?1",
        )?;
        let rows = statement.query_map([i64::try_from(limit).unwrap_or(i64::MAX)], |row| {
            row.get::<_, String>(0)
        })?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    /// Releases a containment latch only after its deadline. Missing or
    /// malformed deadlines are treated as expired so persisted corruption can
    /// never leave a server permanently locked after a restart.
    pub fn release_expired_anti_raid_latch(
        &self,
        guild_id: &str,
        now_seconds: i64,
    ) -> Result<bool> {
        let mut conn = self.conn.lock().expect("store mutex poisoned");
        let tx = conn.transaction()?;
        let latch_active: Option<String> = tx
            .query_row(
                "SELECT value FROM settings WHERE guild_id=?1 AND key='security.anti_raid.latch_active'",
                [guild_id],
                |row| row.get(0),
            )
            .optional()?;
        if latch_active.as_deref() != Some("true") {
            return Ok(false);
        }
        let gate_until: Option<String> = tx
            .query_row(
                "SELECT value FROM settings WHERE guild_id=?1 AND key='security.anti_raid.gate_until'",
                [guild_id],
                |row| row.get(0),
            )
            .optional()?;
        let expired = match gate_until
            .as_deref()
            .and_then(|value| value.parse::<i64>().ok())
        {
            Some(gate_until) => gate_until <= now_seconds,
            None => true,
        };
        if !expired {
            return Ok(false);
        }
        let previous_gate: Option<String> = tx
            .query_row(
                "SELECT value FROM settings WHERE guild_id=?1 AND key='security.anti_raid.previous_gate_enabled'",
                [guild_id],
                |row| row.get(0),
            )
            .optional()?;
        let previous_gate = previous_gate
            .as_deref()
            .and_then(|value| value.parse::<bool>().ok())
            .unwrap_or(false);
        let updated_at = Utc::now().timestamp_millis();
        for (key, value) in [
            ("security.anti_raid.latch_active", "false".to_string()),
            ("security.join_gate.enabled", previous_gate.to_string()),
            (
                "security.anti_raid.previous_gate_enabled",
                "false".to_string(),
            ),
        ] {
            tx.execute(
                "INSERT INTO settings(guild_id,key,value,updated_at) VALUES(?1,?2,?3,?4) ON CONFLICT(guild_id,key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at",
                params![guild_id, key, value, updated_at],
            )?;
        }
        tx.commit()?;
        Ok(true)
    }

    /// Replace a setting only when its current serialized value is exactly the
    /// value read by the caller. This is the compare-and-swap primitive used by
    /// editors that expose optimistic revisions (for example Studio templates)
    /// so two browser tabs cannot silently overwrite one another.
    pub fn compare_and_swap_setting(
        &self,
        guild_id: &str,
        key: &str,
        expected_value: &str,
        replacement_value: &str,
    ) -> Result<bool> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let changed = conn.execute(
            "UPDATE settings SET value=?3,updated_at=?4 WHERE guild_id=?1 AND key=?2 AND value=?5",
            params![
                guild_id,
                key,
                replacement_value,
                Utc::now().timestamp_millis(),
                expected_value
            ],
        )?;
        Ok(changed == 1)
    }

    /// Atomically replaces a Studio template setting and appends its revision.
    /// The revision is committed only when the compare-and-swap succeeds.
    #[allow(clippy::too_many_arguments)]
    pub fn compare_and_swap_studio_template(
        &self,
        guild_id: &str,
        key: &str,
        expected_value: &str,
        replacement_value: &str,
        template_id: &str,
        revision: u64,
        created_by: &str,
    ) -> Result<bool> {
        let mut conn = self.conn.lock().expect("store mutex poisoned");
        let tx = conn.transaction()?;
        let changed = tx.execute(
            "UPDATE settings SET value=?3,updated_at=?4 WHERE guild_id=?1 AND key=?2 AND value=?5",
            params![
                guild_id,
                key,
                replacement_value,
                Utc::now().timestamp_millis(),
                expected_value
            ],
        )?;
        if changed == 0 {
            return Ok(false);
        }
        tx.execute(
            "INSERT INTO studio_template_revisions(guild_id,template_id,revision,template_json,created_at,created_by) VALUES(?1,?2,?3,?4,?5,?6)",
            params![
                guild_id,
                template_id,
                i64::try_from(revision).unwrap_or(i64::MAX),
                replacement_value,
                Utc::now().timestamp_millis(),
                created_by
            ],
        )?;
        tx.commit()?;
        Ok(true)
    }

    /// Creates a template setting and its first revision in one transaction.
    #[allow(clippy::too_many_arguments)]
    pub fn insert_studio_template(
        &self,
        guild_id: &str,
        key: &str,
        value: &str,
        prefix: &str,
        limit: u64,
        template_id: &str,
        created_by: &str,
    ) -> Result<bool> {
        let mut conn = self.conn.lock().expect("store mutex poisoned");
        let tx = conn.transaction()?;
        let existing: Option<String> = tx
            .query_row(
                "SELECT value FROM settings WHERE guild_id=?1 AND key=?2",
                params![guild_id, key],
                |row| row.get(0),
            )
            .optional()?;
        if existing.is_some() {
            return Ok(false);
        }
        let pattern = format!("{prefix}%");
        let count: i64 = tx.query_row(
            "SELECT COUNT(*) FROM settings WHERE guild_id=?1 AND key LIKE ?2",
            params![guild_id, pattern],
            |row| row.get(0),
        )?;
        if count < 0 || count as u64 >= limit {
            return Ok(false);
        }
        let now = Utc::now().timestamp_millis();
        tx.execute(
            "INSERT INTO settings(guild_id,key,value,updated_at) VALUES(?1,?2,?3,?4)",
            params![guild_id, key, value, now],
        )?;
        tx.execute(
            "INSERT INTO studio_template_revisions(guild_id,template_id,revision,template_json,created_at,created_by) VALUES(?1,?2,1,?3,?4,?5)",
            params![guild_id, template_id, value, now, created_by],
        )?;
        tx.commit()?;
        Ok(true)
    }

    pub fn record_studio_template_revision(
        &self,
        guild_id: &str,
        template_id: &str,
        revision: u64,
        template_json: &str,
        created_by: &str,
    ) -> Result<()> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.execute(
            "INSERT INTO studio_template_revisions(guild_id,template_id,revision,template_json,created_at,created_by) VALUES(?1,?2,?3,?4,?5,?6)",
            params![
                guild_id,
                template_id,
                i64::try_from(revision).unwrap_or(i64::MAX),
                template_json,
                Utc::now().timestamp_millis(),
                created_by
            ],
        )?;
        Ok(())
    }

    pub fn studio_template_revisions(
        &self,
        guild_id: &str,
        template_id: &str,
        limit: u64,
    ) -> Result<Vec<StudioTemplateRevisionRecord>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let limit = i64::try_from(limit.clamp(1, 100)).unwrap_or(100);
        let mut stmt = conn.prepare("SELECT guild_id,template_id,revision,template_json,created_at,created_by FROM studio_template_revisions WHERE guild_id=?1 AND template_id=?2 ORDER BY revision DESC LIMIT ?3")?;
        let rows = stmt.query_map(params![guild_id, template_id, limit], |row| {
            Ok(StudioTemplateRevisionRecord {
                guild_id: row.get(0)?,
                template_id: row.get(1)?,
                revision: row.get::<_, i64>(2)?.try_into().unwrap_or(0),
                template_json: row.get(3)?,
                created_at: row.get(4)?,
                created_by: row.get(5)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn studio_template_revision(
        &self,
        guild_id: &str,
        template_id: &str,
        revision: u64,
    ) -> Result<Option<StudioTemplateRevisionRecord>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        Ok(conn
            .query_row(
                "SELECT guild_id,template_id,revision,template_json,created_at,created_by FROM studio_template_revisions WHERE guild_id=?1 AND template_id=?2 AND revision=?3",
                params![guild_id, template_id, i64::try_from(revision).unwrap_or(i64::MAX)],
                |row| {
                    Ok(StudioTemplateRevisionRecord {
                        guild_id: row.get(0)?,
                        template_id: row.get(1)?,
                        revision: row.get::<_, i64>(2)?.try_into().unwrap_or(0),
                        template_json: row.get(3)?,
                        created_at: row.get(4)?,
                        created_by: row.get(5)?,
                    })
                },
            )
            .optional()?)
    }

    /// Insert a new namespaced setting while enforcing its quota in the same
    /// SQLite transaction. Updates to an existing key are deliberately not
    /// counted as new entries.
    pub fn insert_setting_bounded(
        &self,
        guild_id: &str,
        key: &str,
        value: &str,
        prefix: &str,
        limit: u64,
    ) -> Result<bool> {
        let mut conn = self.conn.lock().expect("store mutex poisoned");
        let tx = conn.transaction()?;
        let existing: Option<String> = tx
            .query_row(
                "SELECT value FROM settings WHERE guild_id=?1 AND key=?2",
                params![guild_id, key],
                |row| row.get(0),
            )
            .optional()?;
        if existing.is_some() {
            return Ok(false);
        }
        let pattern = format!("{prefix}%");
        let count: i64 = tx.query_row(
            "SELECT COUNT(*) FROM settings WHERE guild_id=?1 AND key LIKE ?2",
            params![guild_id, pattern],
            |row| row.get(0),
        )?;
        if count < 0 || count as u64 >= limit {
            return Ok(false);
        }
        tx.execute(
            "INSERT INTO settings(guild_id,key,value,updated_at) VALUES(?1,?2,?3,?4)",
            params![guild_id, key, value, Utc::now().timestamp_millis()],
        )?;
        tx.commit()?;
        Ok(true)
    }

    pub fn settings_with_prefix(
        &self,
        guild_id: &str,
        prefix: &str,
    ) -> Result<Vec<(String, String)>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let pattern = format!("{prefix}%");
        let mut stmt = conn.prepare(
            "SELECT key,value FROM settings WHERE guild_id=?1 AND key LIKE ?2 ORDER BY updated_at DESC, key",
        )?;
        let rows = stmt.query_map(params![guild_id, pattern], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn delete_setting(&self, guild_id: &str, key: &str) -> Result<bool> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        Ok(conn.execute(
            "DELETE FROM settings WHERE guild_id=?1 AND key=?2",
            params![guild_id, key],
        )? > 0)
    }

    /// Locate a panel created by the legacy slash command without touching
    /// unrelated messages or using references from another guild.
    pub fn ticket_panel_message(&self, guild_id: &str, channel_id: &str) -> Result<Option<String>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let mut statement = conn.prepare("SELECT key,value FROM settings WHERE guild_id=?1 AND key LIKE 'support.panel.%' ORDER BY key")?;
        for row in statement.query_map([guild_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })? {
            let (key, raw) = row?;
            let Ok(value) = serde_json::from_str::<serde_json::Value>(&raw) else {
                continue;
            };
            let matches = value["channel_id"].as_str() == Some(channel_id)
                || value["channel_id"]
                    .as_u64()
                    .is_some_and(|id| id.to_string() == channel_id);
            if matches
                && let Some(id) = key
                    .strip_prefix("support.panel.")
                    .filter(|id| id.parse::<u64>().is_ok_and(|id| id > 0))
            {
                return Ok(Some(id.to_string()));
            }
        }
        Ok(None)
    }

    pub fn count_settings_prefix(&self, guild_id: &str, prefix: &str) -> Result<u64> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let pattern = format!("{prefix}%");
        let count = conn.query_row(
            "SELECT COUNT(*) FROM settings WHERE guild_id=?1 AND key LIKE ?2",
            params![guild_id, pattern],
            |row| row.get::<_, i64>(0),
        )?;
        Ok(count.try_into().unwrap_or(u64::MAX))
    }

    /// Export the guild-scoped configuration and durable module state without
    /// including Discord message bodies or session/entitlement secrets.
    pub fn export_guild(&self, guild_id: &str) -> Result<serde_json::Value> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let mut settings = Vec::new();
        let mut stmt = conn
            .prepare("SELECT key,value,updated_at FROM settings WHERE guild_id=?1 ORDER BY key")?;
        for row in stmt.query_map([guild_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })? {
            let (key, value, updated_at) = row?;
            let lower_key = key.to_ascii_lowercase();
            if ["secret", "token", "webhook", "credential"]
                .iter()
                .any(|needle| lower_key.contains(needle))
            {
                continue;
            }
            settings.push(serde_json::json!({
                "key": key,
                "value": value,
                "updatedAt": updated_at,
            }));
        }

        let mut tags = Vec::new();
        let mut stmt = conn.prepare(
            "SELECT name,content,author_id,created_at FROM tags WHERE guild_id=?1 ORDER BY name",
        )?;
        for row in stmt.query_map([guild_id], |row| {
            Ok(serde_json::json!({
                "name": row.get::<_, String>(0)?,
                "content": row.get::<_, String>(1)?,
                "authorId": row.get::<_, String>(2)?,
                "createdAt": row.get::<_, i64>(3)?,
            }))
        })? {
            tags.push(row?);
        }

        let mut birthdays = Vec::new();
        let mut stmt = conn.prepare(
            "SELECT user_id,month,day,created_at,updated_at FROM birthdays WHERE guild_id=?1 ORDER BY user_id",
        )?;
        for row in stmt.query_map([guild_id], |row| {
            Ok(serde_json::json!({
                "userId": row.get::<_, String>(0)?,
                "month": row.get::<_, u32>(1)?,
                "day": row.get::<_, u32>(2)?,
                "createdAt": row.get::<_, i64>(3)?,
                "updatedAt": row.get::<_, i64>(4)?,
            }))
        })? {
            birthdays.push(row?);
        }

        let mut workflows = Vec::new();
        let mut stmt = conn.prepare(
            "SELECT id,name,trigger,condition,action,payload,enabled,created_at FROM workflows WHERE guild_id=?1 ORDER BY id",
        )?;
        for row in stmt.query_map([guild_id], |row| {
            Ok(serde_json::json!({
                "id": row.get::<_, i64>(0)?,
                "name": row.get::<_, String>(1)?,
                "trigger": row.get::<_, String>(2)?,
                "condition": row.get::<_, String>(3)?,
                "action": row.get::<_, String>(4)?,
                "payload": row.get::<_, String>(5)?,
                "enabled": row.get::<_, i64>(6)? != 0,
                "createdAt": row.get::<_, i64>(7)?,
            }))
        })? {
            workflows.push(row?);
        }

        Ok(serde_json::json!({
            "version": 1,
            "guildId": guild_id,
            "exportedAt": Utc::now().to_rfc3339(),
            "settings": settings,
            "tags": tags,
            "workflows": workflows,
            "birthdays": birthdays,
        }))
    }

    /// Export user-associated data for the Discord privacy command. The query is
    /// always bounded to the authenticated guild and omits moderator identities
    /// from moderation cases.
    pub fn export_user(&self, guild_id: &str, user_id: &str) -> Result<serde_json::Value> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let mut cases = Vec::new();
        let mut stmt = conn.prepare(
            "SELECT id,type,target_id,reason,duration_ms,created_at FROM cases WHERE guild_id=?1 AND target_id=?2 ORDER BY id",
        )?;
        for row in stmt.query_map(params![guild_id, user_id], |row| {
            Ok(serde_json::json!({
                "id": row.get::<_, i64>(0)?,
                "type": row.get::<_, String>(1)?,
                "targetId": row.get::<_, String>(2)?,
                "reason": row.get::<_, String>(3)?,
                "durationMs": row.get::<_, Option<i64>>(4)?,
                "createdAt": row.get::<_, i64>(5)?,
            }))
        })? {
            cases.push(row?);
        }
        let mut voluntary = Vec::new();
        let mut stmt = conn.prepare(
            "SELECT 'afk' AS kind, reason, since FROM afk WHERE guild_id=?1 AND user_id=?2
             UNION ALL SELECT 'level' AS kind, CAST(xp AS TEXT), 0 FROM levels WHERE guild_id=?1 AND user_id=?2
             UNION ALL SELECT 'tag' AS kind, name, created_at FROM tags WHERE guild_id=?1 AND author_id=?2
             UNION ALL SELECT 'birthday' AS kind, printf('%02d-%02d', month, day), created_at FROM birthdays WHERE guild_id=?1 AND user_id=?2
             UNION ALL SELECT 'economy' AS kind, CAST(balance AS TEXT), created_at FROM economy_accounts WHERE guild_id=?1 AND user_id=?2
             UNION ALL SELECT 'shop_order' AS kind, printf('%s: %d (%s)', product_name, price, status), created_at FROM economy_orders WHERE guild_id=?1 AND user_id=?2
             UNION ALL SELECT 'economy_transaction' AS kind, printf('%+d %s', amount, reason), created_at FROM economy_ledger WHERE guild_id=?1 AND user_id=?2
             UNION ALL SELECT 'xp_event' AS kind, printf('%+d %s', amount, source), created_at FROM xp_events WHERE guild_id=?1 AND user_id=?2
             UNION ALL SELECT 'achievement_activity' AS kind, printf('%s: %d', kind, value), 0 FROM achievement_activity WHERE guild_id=?1 AND user_id=?2
             UNION ALL SELECT 'achievement' AS kind, achievement_key, unlocked_at FROM achievements WHERE guild_id=?1 AND user_id=?2
             ORDER BY kind",
        )?;
        for row in stmt.query_map(params![guild_id, user_id], |row| {
            Ok(serde_json::json!({
                "kind": row.get::<_, String>(0)?,
                "value": row.get::<_, String>(1)?,
                "createdAt": row.get::<_, i64>(2)?,
            }))
        })? {
            voluntary.push(row?);
        }
        let mut suggestions = Vec::new();
        let mut stmt = conn.prepare(
            "SELECT id,content,status,created_at FROM suggestions WHERE guild_id=?1 AND author_id=?2 ORDER BY id",
        )?;
        for row in stmt.query_map(params![guild_id, user_id], |row| {
            Ok(serde_json::json!({
                "id": row.get::<_, i64>(0)?,
                "content": row.get::<_, String>(1)?,
                "status": row.get::<_, String>(2)?,
                "createdAt": row.get::<_, i64>(3)?,
            }))
        })? {
            suggestions.push(row?);
        }
        let mut tickets = Vec::new();
        let mut stmt = conn.prepare(
            "SELECT id,channel_id,status,created_at FROM tickets WHERE guild_id=?1 AND opener_id=?2 ORDER BY id",
        )?;
        for row in stmt.query_map(params![guild_id, user_id], |row| {
            Ok(serde_json::json!({
                "id": row.get::<_, i64>(0)?,
                "channelId": row.get::<_, String>(1)?,
                "status": row.get::<_, String>(2)?,
                "createdAt": row.get::<_, i64>(3)?,
            }))
        })? {
            tickets.push(row?);
        }
        let mut events = Vec::new();
        let mut stmt = conn.prepare(
            "SELECT event_id,status,created_at,checked_in_at FROM event_registrations WHERE guild_id=?1 AND user_id=?2 ORDER BY event_id",
        )?;
        for row in stmt.query_map(params![guild_id, user_id], |row| {
            Ok(serde_json::json!({
                "eventId": row.get::<_, String>(0)?,
                "status": row.get::<_, String>(1)?,
                "createdAt": row.get::<_, i64>(2)?,
                "checkedInAt": row.get::<_, Option<i64>>(3)?,
            }))
        })? {
            events.push(row?);
        }
        Ok(serde_json::json!({
            "version": 1,
            "guildId": guild_id,
            "userId": user_id,
            "exportedAt": Utc::now().to_rfc3339(),
            "moderationCases": cases,
            "voluntary": voluntary,
            "suggestions": suggestions,
            "tickets": tickets,
            "eventRegistrations": events,
        }))
    }

    /// Erase voluntary user data while retaining moderation evidence.
    pub fn purge_user(&self, guild_id: &str, user_id: &str) -> Result<serde_json::Value> {
        let mut conn = self.conn.lock().expect("store mutex poisoned");
        let tx = conn.transaction()?;
        let mut deleted = serde_json::Map::new();
        for (name, statement) in [
            (
                "suggestion_votes",
                "DELETE FROM suggestion_votes WHERE suggestion_id IN (SELECT id FROM suggestions WHERE guild_id=?2 AND author_id=?1) OR (user_id=?1 AND suggestion_id IN (SELECT id FROM suggestions WHERE guild_id=?2))",
            ),
            (
                "giveaway_entries",
                "DELETE FROM giveaway_entries WHERE user_id=?1 AND giveaway_id IN (SELECT id FROM giveaways WHERE guild_id=?2)",
            ),
            (
                "poll_votes",
                "DELETE FROM poll_votes WHERE user_id=?1 AND poll_id IN (SELECT id FROM polls WHERE guild_id=?2)",
            ),
            (
                "scheduled_reminders",
                "DELETE FROM scheduled_actions WHERE guild_id=?2 AND type='reminder' AND target_id=?1",
            ),
            (
                "event_registrations",
                "DELETE FROM event_registrations WHERE guild_id=?2 AND user_id=?1",
            ),
            ("afk", "DELETE FROM afk WHERE guild_id=?2 AND user_id=?1"),
            (
                "achievements",
                "DELETE FROM achievements WHERE guild_id=?2 AND user_id=?1",
            ),
            (
                "achievement_activity",
                "DELETE FROM achievement_activity WHERE guild_id=?2 AND user_id=?1",
            ),
            (
                "achievement_events",
                "DELETE FROM achievement_events WHERE guild_id=?2 AND user_id=?1",
            ),
            (
                "achievement_voice",
                "DELETE FROM achievement_voice WHERE guild_id=?2 AND user_id=?1",
            ),
            (
                "achievement_links",
                "DELETE FROM achievement_links WHERE guild_id=?2 AND user_id=?1",
            ),
            (
                "levels",
                "DELETE FROM levels WHERE guild_id=?2 AND user_id=?1",
            ),
            (
                "xp_events",
                "DELETE FROM xp_events WHERE guild_id=?2 AND user_id=?1",
            ),
            (
                "voice_sessions",
                "DELETE FROM voice_sessions WHERE guild_id=?2 AND user_id=?1",
            ),
            (
                "birthdays",
                "DELETE FROM birthdays WHERE guild_id=?2 AND user_id=?1",
            ),
            (
                "shop_notifications",
                "DELETE FROM scheduled_actions WHERE guild_id=?2 AND type='shop_notice' AND target_id IN (SELECT CAST(id AS TEXT) FROM economy_orders WHERE guild_id=?2 AND user_id=?1)",
            ),
            (
                "economy_orders",
                "DELETE FROM economy_orders WHERE guild_id=?2 AND user_id=?1",
            ),
            (
                "economy_accounts",
                "DELETE FROM economy_accounts WHERE guild_id=?2 AND user_id=?1",
            ),
            (
                "economy_ledger",
                "DELETE FROM economy_ledger WHERE guild_id=?2 AND user_id=?1",
            ),
            (
                "economy_cooldowns",
                "DELETE FROM economy_cooldowns WHERE guild_id=?2 AND user_id=?1",
            ),
            (
                "tags",
                "DELETE FROM tags WHERE guild_id=?2 AND author_id=?1",
            ),
            (
                "suggestions",
                "DELETE FROM suggestions WHERE guild_id=?2 AND author_id=?1",
            ),
        ] {
            let count = tx.execute(statement, params![user_id, guild_id])?;
            if count > 0 {
                deleted.insert(name.to_string(), serde_json::json!(count));
            }
        }
        tx.commit()?;
        Ok(serde_json::json!({
            "deleted": deleted,
            "retained": ["moderationCases", "infractions", "quarantine"],
        }))
    }

    /// Import only the versioned, guild-scoped configuration produced by
    /// `export_guild`. The target guild always comes from the authenticated
    /// caller; the source `guildId` in the document is informational only.
    /// Secrets and unsupported automation shapes are rejected before any write.
    pub fn prepare_guild_config_import(
        guild_id: &str,
        document: &serde_json::Value,
    ) -> Result<PreparedConfigImport> {
        if guild_id.trim().is_empty() || guild_id.len() > 64 {
            bail!("invalid_target_guild");
        }
        if document.to_string().len() > 1_000_000 {
            bail!("config_too_large");
        }
        let object = document
            .as_object()
            .ok_or_else(|| anyhow!("invalid_config_document"))?;
        if object.get("version").and_then(serde_json::Value::as_i64) != Some(1) {
            bail!("unsupported_config_version");
        }
        let settings = object
            .get("settings")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| anyhow!("invalid_settings"))?;
        let tags = object
            .get("tags")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| anyhow!("invalid_tags"))?;
        let workflows = object
            .get("workflows")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| anyhow!("invalid_workflows"))?;
        if object
            .get("birthdays")
            .is_some_and(|value| !value.is_array())
        {
            bail!("invalid_birthdays");
        }
        let birthdays = object
            .get("birthdays")
            .and_then(serde_json::Value::as_array)
            .cloned()
            .unwrap_or_default();
        if settings.len() > 200
            || tags.len() > 100
            || workflows.len() > 100
            || birthdays.len() > 500
        {
            bail!("config_limits_exceeded");
        }

        let secret_needles = ["secret", "token", "webhook", "credential"];
        let mut seen_settings = std::collections::HashSet::new();
        let mut parsed_settings = Vec::with_capacity(settings.len());
        for item in settings {
            let key = item
                .get("key")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| anyhow!("invalid_setting_key"))?
                .trim()
                .to_string();
            let value = item
                .get("value")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| anyhow!("invalid_setting_value"))?
                .to_string();
            let lower_key = key.to_ascii_lowercase();
            if !(1..=100).contains(&key.len()) || value.len() > 4_000 {
                bail!("invalid_setting_bounds");
            }
            if secret_needles
                .iter()
                .any(|needle| lower_key.contains(needle))
            {
                bail!("secret_setting_rejected");
            }
            if !seen_settings.insert(key.clone()) {
                bail!("duplicate_setting_key");
            }
            parsed_settings.push((key, value));
        }

        let mut parsed_tags = Vec::with_capacity(tags.len());
        for item in tags {
            let name = item
                .get("name")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| anyhow!("invalid_tag_name"))?
                .trim()
                .to_string();
            let content = item
                .get("content")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| anyhow!("invalid_tag_content"))?
                .to_string();
            let author_id = item
                .get("authorId")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| anyhow!("invalid_tag_author"))?
                .trim()
                .to_string();
            if !(1..=32).contains(&name.len())
                || !(1..=2_000).contains(&content.len())
                || !(1..=64).contains(&author_id.len())
            {
                bail!("invalid_tag_bounds");
            }
            if parsed_tags.iter().any(|(previous, _, _)| previous == &name) {
                bail!("duplicate_tag");
            }
            parsed_tags.push((name, content, author_id));
        }

        let mut parsed_workflows = Vec::with_capacity(workflows.len());
        for item in workflows {
            let name = item
                .get("name")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| anyhow!("invalid_workflow_name"))?
                .trim()
                .to_string();
            let trigger = item
                .get("trigger")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| anyhow!("invalid_workflow_trigger"))?
                .to_string();
            let condition = item
                .get("condition")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .trim()
                .to_string();
            let action = item
                .get("action")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| anyhow!("invalid_workflow_action"))?
                .to_string();
            let payload = item
                .get("payload")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| anyhow!("invalid_workflow_payload"))?
                .trim()
                .to_string();
            if item.get("enabled").is_some_and(|value| !value.is_boolean()) {
                bail!("invalid_workflow_enabled");
            }
            let enabled = item
                .get("enabled")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(true);
            let payload_is_valid = match action.as_str() {
                "reply" => (1..=1_000).contains(&payload.len()),
                "react" => is_valid_workflow_reaction(&payload),
                _ => false,
            };
            if !(1..=50).contains(&name.len())
                || trigger != "message"
                || !payload_is_valid
                || condition.len() > 200
            {
                bail!("unsupported_workflow");
            }
            if parsed_workflows
                .iter()
                .any(|(previous, _, _, _, _)| previous == &name)
            {
                bail!("duplicate_workflow");
            }
            parsed_workflows.push((name, condition, action, payload, enabled));
        }

        let mut parsed_birthdays = Vec::with_capacity(birthdays.len());
        for item in &birthdays {
            let user_id = item
                .get("userId")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| anyhow!("invalid_birthday_user"))?
                .trim()
                .to_string();
            let month = item
                .get("month")
                .and_then(serde_json::Value::as_u64)
                .ok_or_else(|| anyhow!("invalid_birthday_month"))?;
            let day = item
                .get("day")
                .and_then(serde_json::Value::as_u64)
                .ok_or_else(|| anyhow!("invalid_birthday_day"))?;
            if !(1..=64).contains(&user_id.len())
                || !(1..=12).contains(&month)
                || !(1..=31).contains(&day)
            {
                bail!("invalid_birthday");
            }
            parsed_birthdays.push((user_id, month as u32, day as u32));
        }

        Ok(PreparedConfigImport {
            settings: parsed_settings,
            tags: parsed_tags,
            workflows: parsed_workflows,
            birthdays: parsed_birthdays,
        })
    }

    pub fn import_guild_config(
        &self,
        guild_id: &str,
        document: &serde_json::Value,
    ) -> Result<ConfigImportSummary> {
        let prepared = Self::prepare_guild_config_import(guild_id, document)?;
        let skipped = prepared
            .settings
            .iter()
            .map(|(key, _)| SkippedImportSetting {
                key: key.clone(),
                reason: "requires_authenticated_feature_validation".into(),
            })
            .collect::<Vec<_>>();
        self.apply_guild_config_import(
            guild_id,
            &prepared,
            "config-import",
            &[],
            &skipped,
            &ConfigImportLimits::default(),
        )
    }

    pub fn validate_guild_config_import_limits(
        &self,
        guild_id: &str,
        prepared: &PreparedConfigImport,
        limits: &ConfigImportLimits,
    ) -> Result<()> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let tx = conn.unchecked_transaction()?;
        Self::validate_import_limits_on_tx(&tx, guild_id, prepared, limits)
    }
    fn validate_import_limits_on_tx(
        tx: &rusqlite::Transaction<'_>,
        guild_id: &str,
        prepared: &PreparedConfigImport,
        limits: &ConfigImportLimits,
    ) -> Result<()> {
        let parsed_tags = &prepared.tags;
        let parsed_workflows = &prepared.workflows;
        // Check merged counts under the same lock/transaction as publication.
        if !parsed_tags.is_empty() {
            let mut names = tx
                .prepare("SELECT name FROM tags WHERE guild_id=?1")?
                .query_map([guild_id], |row| row.get::<_, String>(0))?
                .collect::<rusqlite::Result<std::collections::HashSet<_>>>()?;
            for (name, content, _) in parsed_tags {
                if content.chars().count() > limits.tag_length {
                    bail!("import_tag_length_exceeded");
                }
                names.insert(name.clone());
            }
            if names.len() > limits.tags {
                bail!("import_tag_quota_exceeded");
            }
        }
        if !parsed_workflows.is_empty() {
            let existing: i64 = tx.query_row(
                "SELECT COUNT(*) FROM workflows WHERE guild_id=?1",
                [guild_id],
                |row| row.get(0),
            )?;
            let mut count = existing;
            for (name, _, action, payload, _) in parsed_workflows {
                if action == "reply" && payload.len() > limits.reply_length {
                    bail!("import_reply_length_exceeded");
                }
                let replaced:i64=tx.query_row("SELECT COUNT(*) FROM workflows WHERE guild_id=?1 AND name=?2 AND trigger='message'",params![guild_id,name],|row|row.get(0))?;
                count = count - replaced + 1;
            }
            if count > limits.workflows as i64 {
                bail!("import_workflow_quota_exceeded");
            }
        }
        Ok(())
    }

    pub fn apply_guild_config_import(
        &self,
        guild_id: &str,
        prepared: &PreparedConfigImport,
        actor_id: &str,
        features: &[ConfigImportFeature],
        skipped_settings: &[SkippedImportSetting],
        limits: &ConfigImportLimits,
    ) -> Result<ConfigImportSummary> {
        let PreparedConfigImport {
            tags: parsed_tags,
            workflows: parsed_workflows,
            birthdays: parsed_birthdays,
            ..
        } = prepared;
        let conn = self.conn.lock().expect("store mutex poisoned");
        let tx = conn.unchecked_transaction()?;
        Self::validate_import_limits_on_tx(&tx, guild_id, prepared, limits)?;
        for feature in features {
            let args = (
                &tx,
                guild_id,
                feature.key.as_str(),
                feature.enabled,
                feature.config_json.as_str(),
                Some(feature.expected_revision),
                actor_id,
                feature.projections.as_slice(),
            );
            match &feature.subscription {
                ImportSubscription::None => Self::publish_feature_setting_on_tx(
                    args.0, args.1, args.2, args.3, args.4, args.5, args.6, args.7,
                )?,
                ImportSubscription::YouTube(value) => Self::publish_youtube_feature_setting_on_tx(
                    args.0,
                    args.1,
                    args.2,
                    args.3,
                    args.4,
                    args.5,
                    args.6,
                    args.7,
                    value.as_ref(),
                )?,
                ImportSubscription::Rss(value) => Self::publish_rss_feature_setting_on_tx(
                    args.0,
                    args.1,
                    args.2,
                    args.3,
                    args.4,
                    args.5,
                    args.6,
                    args.7,
                    value.as_ref(),
                )?,
                ImportSubscription::Bluesky(value) => Self::publish_bluesky_feature_setting_on_tx(
                    args.0,
                    args.1,
                    args.2,
                    args.3,
                    args.4,
                    args.5,
                    args.6,
                    args.7,
                    value.as_ref(),
                )?,
                ImportSubscription::TikTok(value) => Self::publish_tiktok_feature_setting_on_tx(
                    args.0,
                    args.1,
                    args.2,
                    args.3,
                    args.4,
                    args.5,
                    args.6,
                    args.7,
                    value.as_ref(),
                )?,
                ImportSubscription::Twitch(value) => Self::publish_twitch_feature_setting_on_tx(
                    args.0,
                    args.1,
                    args.2,
                    args.3,
                    args.4,
                    args.5,
                    args.6,
                    args.7,
                    value.as_ref(),
                )?,
                ImportSubscription::Instagram(value) => {
                    Self::publish_instagram_feature_setting_on_tx(
                        args.0,
                        args.1,
                        args.2,
                        args.3,
                        args.4,
                        args.5,
                        args.6,
                        args.7,
                        value.as_ref(),
                    )?
                }
                ImportSubscription::Kick(value) => Self::publish_kick_feature_setting_on_tx(
                    args.0,
                    args.1,
                    args.2,
                    args.3,
                    args.4,
                    args.5,
                    args.6,
                    args.7,
                    value.as_ref(),
                )?,
            };
        }
        for (name, content, _author_id) in parsed_tags {
            tx.execute(
                "INSERT INTO tags(guild_id,name,content,author_id,created_at) VALUES(?1,?2,?3,?4,?5) ON CONFLICT(guild_id,name) DO UPDATE SET content=excluded.content,author_id=excluded.author_id,created_at=excluded.created_at",
                params![guild_id, name, content, actor_id, Utc::now().timestamp_millis()],
            )?;
        }
        for (name, condition, action, payload, enabled) in parsed_workflows {
            tx.execute(
                "DELETE FROM workflows WHERE guild_id=?1 AND name=?2 AND trigger='message'",
                params![guild_id, name],
            )?;
            tx.execute(
                "INSERT INTO workflows(guild_id,name,trigger,condition,action,payload,enabled,created_at) VALUES(?1,?2,'message',?3,?4,?5,?6,?7)",
                params![guild_id, name, condition, action, payload, i64::from(*enabled), Utc::now().timestamp_millis()],
            )?;
        }
        for (user_id, month, day) in parsed_birthdays {
            tx.execute(
                "INSERT INTO birthdays(guild_id,user_id,month,day,created_at,updated_at) VALUES(?1,?2,?3,?4,?5,?5) ON CONFLICT(guild_id,user_id) DO UPDATE SET month=excluded.month,day=excluded.day,last_announced_year=NULL,updated_at=excluded.updated_at",
                params![guild_id, user_id, month, day, Utc::now().timestamp_millis()],
            )?;
        }
        tx.commit()?;
        Ok(ConfigImportSummary {
            settings: features.len(),
            skipped_settings: skipped_settings.to_vec(),
            tags: parsed_tags.len(),
            workflows: parsed_workflows.len(),
            birthdays: parsed_birthdays.len(),
        })
    }

    /// Erase all guild-scoped operational data. User entitlements and login
    /// sessions are intentionally outside this operation's scope.
    pub fn purge_guild(&self, guild_id: &str) -> Result<()> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let tx = conn.unchecked_transaction()?;
        for statement in [
            "DELETE FROM suggestion_votes WHERE suggestion_id IN (SELECT id FROM suggestions WHERE guild_id=?1)",
            "DELETE FROM suggestions WHERE guild_id=?1",
            "DELETE FROM giveaway_entries WHERE giveaway_id IN (SELECT id FROM giveaways WHERE guild_id=?1)",
            "DELETE FROM giveaway_results WHERE giveaway_id IN (SELECT id FROM giveaways WHERE guild_id=?1)",
            "DELETE FROM giveaways WHERE guild_id=?1",
            "DELETE FROM poll_votes WHERE poll_id IN (SELECT id FROM polls WHERE guild_id=?1)",
            "DELETE FROM polls WHERE guild_id=?1",
            "DELETE FROM workflow_runs WHERE guild_id=?1",
            "DELETE FROM workflows WHERE guild_id=?1",
            "DELETE FROM cases WHERE guild_id=?1",
            "DELETE FROM audit_events WHERE guild_id=?1",
            "DELETE FROM activity_log WHERE guild_id=?1",
            "DELETE FROM scheduled_actions WHERE guild_id=?1",
            "DELETE FROM infractions WHERE guild_id=?1",
            "DELETE FROM afk WHERE guild_id=?1",
            "DELETE FROM tags WHERE guild_id=?1",
            "DELETE FROM levels WHERE guild_id=?1",
            "DELETE FROM xp_events WHERE guild_id=?1",
            "DELETE FROM achievements WHERE guild_id=?1",
            "DELETE FROM achievement_activity WHERE guild_id=?1",
            "DELETE FROM achievement_events WHERE guild_id=?1",
            "DELETE FROM achievement_voice WHERE guild_id=?1",
            "DELETE FROM achievement_links WHERE guild_id=?1",
            "DELETE FROM achievement_threads WHERE guild_id=?1",
            "DELETE FROM welcome_delivery_claims WHERE guild_id=?1",
            "DELETE FROM voice_sessions WHERE guild_id=?1",
            "DELETE FROM birthdays WHERE guild_id=?1",
            "DELETE FROM economy_orders WHERE guild_id=?1",
            "DELETE FROM economy_products WHERE guild_id=?1",
            "DELETE FROM economy_accounts WHERE guild_id=?1",
            "DELETE FROM economy_cooldowns WHERE guild_id=?1",
            "DELETE FROM economy_ledger WHERE guild_id=?1",
            "DELETE FROM temp_channels WHERE guild_id=?1",
            "DELETE FROM stats WHERE guild_id=?1",
            "DELETE FROM tickets WHERE guild_id=?1",
            "DELETE FROM quarantine WHERE guild_id=?1",
            "DELETE FROM starboard WHERE guild_id=?1",
            "DELETE FROM helper_usage WHERE guild_id=?1",
            "DELETE FROM helper_growth_activity_day WHERE guild_id=?1",
            "DELETE FROM helper_growth_activity_day_v2 WHERE guild_id=?1",
            "DELETE FROM helper_growth_retention_record WHERE guild_id=?1",
            "DELETE FROM helper_growth_lifecycle WHERE guild_id=?1",
            "DELETE FROM invite_snapshots WHERE guild_id=?1",
            "DELETE FROM invite_attributions WHERE guild_id=?1",
            "DELETE FROM siwe_nonces WHERE guild_id=?1",
            "DELETE FROM feature_settings WHERE guild_id=?1",
            "DELETE FROM feature_revisions WHERE guild_id=?1",
            "DELETE FROM studio_template_revisions WHERE guild_id=?1",
            "DELETE FROM event_registrations WHERE guild_id=?1",
            "DELETE FROM twitch_subscriptions WHERE guild_id=?1",
            "DELETE FROM youtube_subscriptions WHERE guild_id=?1",
            "DELETE FROM rss_subscriptions WHERE guild_id=?1",
            "DELETE FROM bluesky_subscriptions WHERE guild_id=?1",
            "DELETE FROM reddit_subscriptions WHERE guild_id=?1",
            "DELETE FROM x_subscriptions WHERE guild_id=?1",
            "DELETE FROM tiktok_subscriptions WHERE guild_id=?1",
            "DELETE FROM tiktok_grants WHERE guild_id=?1",
            "DELETE FROM instagram_subscriptions WHERE guild_id=?1",
            "DELETE FROM kick_subscriptions WHERE guild_id=?1",
            "DELETE FROM settings WHERE guild_id=?1",
        ] {
            tx.execute(statement, [guild_id])?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Apply bounded retention to operational data. The sweep is idempotent,
    /// guild-agnostic, and returns counts for an auditable scheduler log.
    pub fn prune_retention(&self, now_ms: i64) -> Result<RetentionSummary> {
        let now = DateTime::<Utc>::from_timestamp_millis(now_ms).unwrap_or_else(Utc::now);
        let cutoff_30d = (now - Duration::days(30)).timestamp_millis();
        let cutoff_90d = (now - Duration::days(90)).timestamp_millis();
        let cutoff_1y = (now - Duration::days(365)).timestamp_millis();
        let cutoff_2y = (now - Duration::days(730)).timestamp_millis();
        let cutoff_date_1y = (now - Duration::days(365)).format("%Y-%m-%d").to_string();
        let cutoff_rfc3339 = (now - Duration::hours(24)).to_rfc3339();
        let cutoff_seconds = (now - Duration::hours(24)).timestamp();

        let mut conn = self.conn.lock().expect("store mutex poisoned");
        let tx = conn.transaction()?;
        let mut deleted = serde_json::Map::new();
        let mut remove = |name: &str, count: usize| {
            if count > 0 {
                deleted.insert(name.to_string(), serde_json::json!(count));
            }
        };

        remove(
            "audit_events",
            tx.execute(
                "DELETE FROM audit_events WHERE created_at < ?1",
                [cutoff_30d],
            )?,
        );
        remove(
            "activity_log",
            tx.execute(
                "DELETE FROM activity_log WHERE created_at < ?1",
                [cutoff_90d],
            )?,
        );
        // Remove the per-guild activity keys with their lifecycle rows. The
        // aggregate daily metrics have no guild identity and remain available.
        tx.execute(
            "DELETE FROM helper_growth_activity_day WHERE guild_id IN (SELECT guild_id FROM helper_growth_lifecycle WHERE departed_at IS NOT NULL AND departed_at < ?1)",
            [cutoff_30d],
        )?;
        tx.execute(
            "DELETE FROM helper_growth_activity_day_v2 WHERE guild_id IN (SELECT guild_id FROM helper_growth_lifecycle WHERE departed_at IS NOT NULL AND departed_at < ?1)",
            [cutoff_30d],
        )?;
        tx.execute(
            "DELETE FROM helper_growth_retention_record WHERE guild_id IN (SELECT guild_id FROM helper_growth_lifecycle WHERE departed_at IS NOT NULL AND departed_at < ?1)",
            [cutoff_30d],
        )?;
        remove(
            "growth_lifecycle",
            tx.execute(
                "DELETE FROM helper_growth_lifecycle WHERE departed_at IS NOT NULL AND departed_at < ?1",
                [cutoff_30d],
            )?,
        );
        remove(
            "infractions",
            tx.execute("DELETE FROM infractions WHERE created_at < ?1", [cutoff_1y])?,
        );
        remove(
            "cases",
            tx.execute("DELETE FROM cases WHERE created_at < ?1", [cutoff_2y])?,
        );
        remove(
            "quarantine",
            tx.execute("DELETE FROM quarantine WHERE created_at < ?1", [cutoff_1y])?,
        );
        remove(
            "scheduled_actions",
            tx.execute(
                "DELETE FROM scheduled_actions WHERE execute_at < ?1",
                [cutoff_90d],
            )?,
        );
        remove(
            "tickets",
            tx.execute(
                "DELETE FROM tickets WHERE closed_at IS NOT NULL AND closed_at < ?1",
                [cutoff_1y],
            )?,
        );
        remove(
            "suggestion_votes",
            tx.execute(
                "DELETE FROM suggestion_votes WHERE suggestion_id IN (SELECT id FROM suggestions WHERE created_at < ?1)",
                [cutoff_1y],
            )?,
        );
        remove(
            "suggestions",
            tx.execute("DELETE FROM suggestions WHERE created_at < ?1", [cutoff_1y])?,
        );
        remove(
            "giveaway_entries",
            tx.execute(
                "DELETE FROM giveaway_entries WHERE giveaway_id IN (SELECT id FROM giveaways WHERE ended=1 AND end_at < ?1)",
                [cutoff_90d],
            )?,
        );
        remove(
            "giveaway_results",
            tx.execute(
                "DELETE FROM giveaway_results WHERE giveaway_id IN (SELECT id FROM giveaways WHERE ended=1 AND end_at < ?1) OR NOT EXISTS (SELECT 1 FROM giveaways WHERE id=giveaway_results.giveaway_id)",
                [cutoff_90d],
            )?,
        );
        remove(
            "giveaways",
            tx.execute(
                "DELETE FROM giveaways WHERE ended=1 AND end_at < ?1",
                [cutoff_90d],
            )?,
        );
        remove(
            "poll_votes",
            tx.execute(
                "DELETE FROM poll_votes WHERE poll_id IN (SELECT id FROM polls WHERE closed=1 AND end_at < ?1)",
                [cutoff_90d],
            )?,
        );
        remove(
            "polls",
            tx.execute(
                "DELETE FROM polls WHERE closed=1 AND end_at < ?1",
                [cutoff_90d],
            )?,
        );
        remove(
            "stats",
            tx.execute("DELETE FROM stats WHERE date < ?1", [&cutoff_date_1y])?,
        );
        remove(
            "xp_events",
            tx.execute("DELETE FROM xp_events WHERE created_at < ?1", [cutoff_1y])?,
        );
        // A gateway disconnect can leave a voice session without a matching
        // leave event. Sessions older than the bounded XP window are stale
        // and must not survive indefinitely or receive retroactive XP.
        remove(
            "voice_sessions",
            tx.execute(
                "DELETE FROM voice_sessions WHERE started_at < ?1",
                [cutoff_seconds],
            )?,
        );
        remove(
            "helper_session_guilds",
            tx.execute(
                "DELETE FROM helper_session_guilds WHERE session_id IN (SELECT id FROM helper_sessions WHERE expires_at < ?1 OR revoked_at < ?1)",
                [&cutoff_rfc3339],
            )?,
        );
        remove(
            "helper_sessions",
            tx.execute(
                "DELETE FROM helper_sessions WHERE expires_at < ?1 OR revoked_at < ?1",
                [&cutoff_rfc3339],
            )?,
        );
        remove(
            "helper_oauth_states",
            tx.execute(
                "DELETE FROM helper_oauth_states WHERE expires_at < ?1 OR used_at < ?1",
                [cutoff_seconds],
            )?,
        );
        tx.commit()?;
        Ok(RetentionSummary {
            deleted: serde_json::Value::Object(deleted),
        })
    }

    pub fn add_xp(&self, guild_id: &str, user_id: &str, amount: i64) -> Result<i64> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.execute(
            "INSERT INTO levels(guild_id,user_id,xp) VALUES(?1,?2,?3) ON CONFLICT(guild_id,user_id) DO UPDATE SET xp=xp+excluded.xp",
            params![guild_id, user_id, amount.max(0)],
        )?;
        Ok(conn.query_row(
            "SELECT xp FROM levels WHERE guild_id=?1 AND user_id=?2",
            params![guild_id, user_id],
            |row| row.get(0),
        )?)
    }

    /// Apply one XP award exactly once and return the resulting balance.
    ///
    /// Discord can redeliver gateway events and a release can replay a job
    /// after a process restart.  The event insert and materialized balance
    /// update therefore happen in one transaction, keyed by the caller's
    /// stable event identifier.  `None` means this event was already applied.
    pub fn add_xp_event(
        &self,
        guild_id: &str,
        user_id: &str,
        event_key: &str,
        source: &str,
        amount: i64,
        created_at: i64,
    ) -> Result<Option<i64>> {
        if guild_id.trim().is_empty()
            || user_id.trim().is_empty()
            || event_key.trim().is_empty()
            || source.trim().is_empty()
            || guild_id.len() > 64
            || user_id.len() > 64
            || event_key.len() > 160
            || source.len() > 48
        {
            bail!("invalid_xp_event");
        }
        let amount = amount.clamp(0, 2_000);
        let mut conn = self.conn.lock().expect("store mutex poisoned");
        let tx = conn.transaction()?;
        let inserted = tx.execute(
            "INSERT OR IGNORE INTO xp_events(guild_id,user_id,event_key,source,amount,created_at) VALUES(?1,?2,?3,?4,?5,?6)",
            params![guild_id, user_id, event_key, source, amount, created_at],
        )?;
        if inserted == 0 {
            tx.commit()?;
            return Ok(None);
        }
        tx.execute(
            "INSERT INTO levels(guild_id,user_id,xp) VALUES(?1,?2,?3) ON CONFLICT(guild_id,user_id) DO UPDATE SET xp=xp+excluded.xp",
            params![guild_id, user_id, amount],
        )?;
        let xp = tx.query_row(
            "SELECT xp FROM levels WHERE guild_id=?1 AND user_id=?2",
            params![guild_id, user_id],
            |row| row.get(0),
        )?;
        tx.commit()?;
        Ok(Some(xp))
    }

    /// Start or replace the active voice session for a member. Replaying the
    /// same gateway event is therefore harmless and a move between channels
    /// cannot leave two active sessions behind.
    pub fn start_voice_session(
        &self,
        guild_id: &str,
        user_id: &str,
        channel_id: &str,
        started_at: i64,
    ) -> Result<()> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.execute(
            "INSERT INTO voice_sessions(guild_id,user_id,channel_id,started_at) VALUES(?1,?2,?3,?4) ON CONFLICT(guild_id,user_id) DO UPDATE SET channel_id=excluded.channel_id, started_at=excluded.started_at",
            params![guild_id, user_id, channel_id, started_at],
        )?;
        Ok(())
    }

    /// Finish a voice session and return bounded whole minutes. The row is
    /// deleted in the same operation so duplicate leave events cannot award
    /// XP twice.
    pub fn finish_voice_session(
        &self,
        guild_id: &str,
        user_id: &str,
        ended_at: i64,
    ) -> Result<Option<i64>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let started: Option<i64> = conn
            .query_row(
                "SELECT started_at FROM voice_sessions WHERE guild_id=?1 AND user_id=?2",
                params![guild_id, user_id],
                |row| row.get(0),
            )
            .optional()?;
        let Some(started_at) = started else {
            return Ok(None);
        };
        conn.execute(
            "DELETE FROM voice_sessions WHERE guild_id=?1 AND user_id=?2",
            params![guild_id, user_id],
        )?;
        Ok(Some(((ended_at - started_at).max(0) / 60).min(24 * 60)))
    }

    pub fn active_voice_session(
        &self,
        guild_id: &str,
        user_id: &str,
    ) -> Result<Option<VoiceSessionRecord>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.query_row(
            "SELECT guild_id,user_id,channel_id,started_at FROM voice_sessions WHERE guild_id=?1 AND user_id=?2",
            params![guild_id, user_id],
            |row| {
                Ok(VoiceSessionRecord {
                    guild_id: row.get(0)?,
                    user_id: row.get(1)?,
                    channel_id: row.get(2)?,
                    started_at: row.get(3)?,
                })
            },
        )
        .optional()
        .map_err(Into::into)
    }

    pub fn level_for(&self, guild_id: &str, user_id: &str) -> Result<i64> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        Ok(conn
            .query_row(
                "SELECT xp FROM levels WHERE guild_id=?1 AND user_id=?2",
                params![guild_id, user_id],
                |row| row.get(0),
            )
            .optional()?
            .unwrap_or(0))
    }

    /// Record a milestone exactly once.  Returning `true` only for the first
    /// insert lets the gateway announce a reward safely when Discord retries
    /// the same message event.
    pub fn unlock_achievement(
        &self,
        guild_id: &str,
        user_id: &str,
        achievement_key: &str,
        threshold: i64,
        unlocked_at: i64,
    ) -> Result<bool> {
        if guild_id.is_empty()
            || user_id.is_empty()
            || achievement_key.is_empty()
            || achievement_key.len() > 96
        {
            bail!("achievement identifiers are invalid");
        }
        let conn = self.conn.lock().expect("store mutex poisoned");
        let changed = conn.execute(
            "INSERT OR IGNORE INTO achievements(guild_id,user_id,achievement_key,threshold,unlocked_at) VALUES(?1,?2,?3,?4,?5)",
            params![guild_id, user_id, achievement_key, threshold.clamp(1, 1_000_000_000), unlocked_at],
        )?;
        Ok(changed == 1)
    }

    pub fn achievements_for(
        &self,
        guild_id: &str,
        user_id: &str,
    ) -> Result<Vec<AchievementRecord>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let mut stmt = conn.prepare(
            "SELECT guild_id,user_id,achievement_key,threshold,unlocked_at FROM achievements WHERE guild_id=?1 AND user_id=?2 ORDER BY unlocked_at ASC, achievement_key ASC",
        )?;
        let rows = stmt.query_map(params![guild_id, user_id], |row| {
            Ok(AchievementRecord {
                guild_id: row.get(0)?,
                user_id: row.get(1)?,
                achievement_key: row.get(2)?,
                threshold: row.get(3)?,
                unlocked_at: row.get(4)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn top_levels(&self, guild_id: &str, limit: u32) -> Result<Vec<LevelRecord>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let mut stmt = conn.prepare(
            "SELECT guild_id,user_id,xp FROM levels WHERE guild_id=?1 ORDER BY xp DESC,user_id ASC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![guild_id, i64::from(limit.min(100))], |row| {
            Ok(LevelRecord {
                guild_id: row.get(0)?,
                user_id: row.get(1)?,
                xp: row.get(2)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Position in the XP ranking (1 = highest XP). Users without a row have
    /// no rank and are represented as `None` by the caller.
    pub fn level_rank(&self, guild_id: &str, user_id: &str) -> Result<Option<u64>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let xp: Option<i64> = conn
            .query_row(
                "SELECT xp FROM levels WHERE guild_id=?1 AND user_id=?2",
                params![guild_id, user_id],
                |row| row.get(0),
            )
            .optional()?;
        let Some(xp) = xp else {
            return Ok(None);
        };
        let higher: i64 = conn.query_row(
            "SELECT COUNT(*) FROM levels WHERE guild_id=?1 AND xp>?2",
            params![guild_id, xp],
            |row| row.get(0),
        )?;
        Ok(Some((higher + 1).try_into().unwrap_or(u64::MAX)))
    }

    pub fn record_message(&self, guild_id: &str, day: &str) -> Result<()> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.execute("INSERT INTO stats(guild_id,date,messages,joins,leaves) VALUES(?1,?2,1,0,0) ON CONFLICT(guild_id,date) DO UPDATE SET messages=messages+1", params![guild_id, day])?;
        Ok(())
    }

    pub fn record_join(&self, guild_id: &str, day: &str) -> Result<()> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.execute("INSERT INTO stats(guild_id,date,messages,joins,leaves) VALUES(?1,?2,0,1,0) ON CONFLICT(guild_id,date) DO UPDATE SET joins=joins+1", params![guild_id, day])?;
        Ok(())
    }

    pub fn record_leave(&self, guild_id: &str, day: &str) -> Result<()> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.execute("INSERT INTO stats(guild_id,date,messages,joins,leaves) VALUES(?1,?2,0,0,1) ON CONFLICT(guild_id,date) DO UPDATE SET leaves=leaves+1", params![guild_id, day])?;
        Ok(())
    }

    /// Upsert one invite counter and return the previously observed usage.
    /// Values are clamped so a malformed Discord response cannot create an
    /// unbounded attribution delta.
    pub fn observe_invite(
        &self,
        guild_id: &str,
        code: &str,
        uses: i64,
        inviter_id: Option<&str>,
    ) -> Result<Option<i64>> {
        let code = code.trim();
        if code.is_empty() || code.len() > 64 {
            bail!("invalid_invite_code");
        }
        let uses = uses.clamp(0, 9_999_999);
        let conn = self.conn.lock().expect("store mutex poisoned");
        let previous = conn
            .query_row(
                "SELECT uses FROM invite_snapshots WHERE guild_id=?1 AND code=?2",
                params![guild_id, code],
                |row| row.get(0),
            )
            .optional()?;
        conn.execute(
            "INSERT INTO invite_snapshots(guild_id,code,uses,inviter_id,updated_at) VALUES(?1,?2,?3,?4,?5) ON CONFLICT(guild_id,code) DO UPDATE SET uses=excluded.uses,inviter_id=COALESCE(excluded.inviter_id,invite_snapshots.inviter_id),updated_at=excluded.updated_at",
            params![guild_id, code, uses, inviter_id, Utc::now().timestamp_millis()],
        )?;
        Ok(previous)
    }

    pub fn record_invite_attribution(
        &self,
        guild_id: &str,
        user_id: &str,
        code: &str,
        inviter_id: Option<&str>,
    ) -> Result<()> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.execute(
            "INSERT INTO invite_attributions(guild_id,user_id,code,inviter_id,joined_at) VALUES(?1,?2,?3,?4,?5) ON CONFLICT(guild_id,user_id) DO UPDATE SET code=excluded.code,inviter_id=excluded.inviter_id,joined_at=excluded.joined_at",
            params![guild_id, user_id, code, inviter_id, Utc::now().timestamp_millis()],
        )?;
        Ok(())
    }

    pub fn invite_attribution(
        &self,
        guild_id: &str,
        user_id: &str,
    ) -> Result<Option<(String, Option<String>)>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        Ok(conn
            .query_row(
                "SELECT code,inviter_id FROM invite_attributions WHERE guild_id=?1 AND user_id=?2",
                params![guild_id, user_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?)
    }

    pub fn invite_attribution_summary(
        &self,
        guild_id: &str,
        limit: u32,
    ) -> Result<Vec<(String, i64)>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let mut stmt = conn.prepare(
            "SELECT code,COUNT(*) FROM invite_attributions WHERE guild_id=?1 GROUP BY code ORDER BY COUNT(*) DESC,code ASC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![guild_id, i64::from(limit.clamp(1, 50))], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn stats_for(&self, guild_id: &str, limit: u32) -> Result<Vec<(String, i64, i64, i64)>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let mut stmt = conn.prepare("SELECT date,messages,joins,leaves FROM stats WHERE guild_id=?1 ORDER BY date DESC LIMIT ?2")?;
        let rows = stmt.query_map(params![guild_id, i64::from(limit.min(365))], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn schedule(
        &self,
        guild_id: &str,
        target_id: &str,
        execute_at: i64,
        payload: &str,
    ) -> Result<i64> {
        self.schedule_typed(guild_id, "reminder", target_id, execute_at, payload)
    }

    pub fn schedule_typed(
        &self,
        guild_id: &str,
        action_type: &str,
        target_id: &str,
        execute_at: i64,
        payload: &str,
    ) -> Result<i64> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.execute("INSERT INTO scheduled_actions(guild_id,type,target_id,execute_at,payload,case_id) VALUES(?1,?2,?3,?4,?5,NULL)", params![guild_id, action_type, target_id, execute_at, payload])?;
        Ok(conn.last_insert_rowid())
    }

    pub fn open_ticket(&self, guild_id: &str, user_id: &str, channel_id: &str) -> Result<()> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.execute(
            "INSERT INTO tickets(guild_id,channel_id,opener_id,status,claimed_by,created_at) VALUES(?1,?3,?2,'open',NULL,?4)",
            params![guild_id, user_id, channel_id, Utc::now().timestamp_millis()],
        )?;
        Ok(())
    }

    pub fn try_open_ticket(
        &self,
        guild_id: &str,
        user_id: &str,
        channel_id: &str,
        max_open: u32,
    ) -> Result<bool> {
        let limit = i64::from(max_open.clamp(1, 10));
        let mut conn = self.conn.lock().expect("store mutex poisoned");
        let tx = conn.transaction()?;
        let open_count: i64 = tx.query_row(
            "SELECT COUNT(*) FROM tickets WHERE guild_id=?1 AND opener_id=?2 AND status='open'",
            params![guild_id, user_id],
            |row| row.get(0),
        )?;
        if open_count >= limit {
            return Ok(false);
        }
        tx.execute(
            "INSERT INTO tickets(guild_id,channel_id,opener_id,status,claimed_by,created_at) VALUES(?1,?3,?2,'open',NULL,?4)",
            params![guild_id, user_id, channel_id, Utc::now().timestamp_millis()],
        )?;
        tx.commit()?;
        Ok(true)
    }

    pub fn active_ticket_for_user(
        &self,
        guild_id: &str,
        user_id: &str,
    ) -> Result<Option<TicketRecord>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        Ok(conn.query_row(
            "SELECT guild_id,opener_id,channel_id,status,claimed_by,category,priority,notes,csat,created_at,closed_at FROM tickets WHERE guild_id=?1 AND opener_id=?2 AND status='open' ORDER BY created_at DESC LIMIT 1",
            params![guild_id, user_id],
            |row| Ok(TicketRecord { guild_id: row.get(0)?, user_id: row.get(1)?, channel_id: row.get(2)?, status: row.get(3)?, claimed_by: row.get(4)?, category: row.get(5)?, priority: row.get(6)?, notes: row.get(7)?, csat: row.get(8)?, created_at: row.get(9)?, closed_at: row.get(10)? }),
        ).optional()?)
    }

    pub fn active_ticket_count_for_user(&self, guild_id: &str, user_id: &str) -> Result<u32> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let count = conn.query_row(
            "SELECT COUNT(*) FROM tickets WHERE guild_id=?1 AND opener_id=?2 AND status='open'",
            params![guild_id, user_id],
            |row| row.get::<_, i64>(0),
        )?;
        Ok(count.try_into().unwrap_or(u32::MAX))
    }

    pub fn ticket_by_channel(&self, channel_id: &str) -> Result<Option<TicketRecord>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        Ok(conn.query_row(
            "SELECT guild_id,opener_id,channel_id,status,claimed_by,category,priority,notes,csat,created_at,closed_at FROM tickets WHERE channel_id=?1",
            [channel_id],
            |row| Ok(TicketRecord { guild_id: row.get(0)?, user_id: row.get(1)?, channel_id: row.get(2)?, status: row.get(3)?, claimed_by: row.get(4)?, category: row.get(5)?, priority: row.get(6)?, notes: row.get(7)?, csat: row.get(8)?, created_at: row.get(9)?, closed_at: row.get(10)? }),
        ).optional()?)
    }

    pub fn claim_ticket(&self, channel_id: &str, user_id: &str) -> Result<bool> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        Ok(conn.execute(
            "UPDATE tickets SET claimed_by=?2 WHERE channel_id=?1 AND status='open' AND (claimed_by IS NULL OR claimed_by=?2)",
            params![channel_id, user_id],
        )? > 0)
    }

    pub fn close_ticket(&self, channel_id: &str) -> Result<bool> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        Ok(conn.execute(
            "UPDATE tickets SET status='closed',closed_at=?2 WHERE channel_id=?1 AND status='open'",
            params![channel_id, Utc::now().timestamp_millis()],
        )? > 0)
    }

    pub fn reopen_ticket(&self, channel_id: &str) -> Result<bool> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        Ok(conn.execute(
            "UPDATE tickets SET status='open',closed_at=NULL WHERE channel_id=?1 AND status='closed'",
            [channel_id],
        )? > 0)
    }

    pub fn set_ticket_priority(&self, channel_id: &str, priority: &str) -> Result<bool> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        Ok(conn.execute(
            "UPDATE tickets SET priority=?2 WHERE channel_id=?1",
            params![channel_id, priority],
        )? > 0)
    }

    pub fn set_ticket_category(&self, channel_id: &str, category: &str) -> Result<bool> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        Ok(conn.execute(
            "UPDATE tickets SET category=?2 WHERE channel_id=?1",
            params![channel_id, category],
        )? > 0)
    }

    pub fn set_ticket_notes(&self, channel_id: &str, notes: &str) -> Result<bool> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        Ok(conn.execute(
            "UPDATE tickets SET notes=?2 WHERE channel_id=?1",
            params![channel_id, notes],
        )? > 0)
    }

    pub fn set_ticket_csat(&self, channel_id: &str, score: i64) -> Result<bool> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        Ok(conn.execute(
            "UPDATE tickets SET csat=?2 WHERE channel_id=?1 AND status='closed'",
            params![channel_id, score],
        )? > 0)
    }

    pub fn register_event(&self, guild_id: &str, event_id: &str, user_id: &str) -> Result<bool> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        Ok(conn.execute(
            "INSERT OR IGNORE INTO event_registrations(guild_id,event_id,user_id,status,created_at,checked_in_at) VALUES(?1,?2,?3,'registered',?4,NULL)",
            params![guild_id, event_id, user_id, Utc::now().timestamp_millis()],
        )? > 0)
    }

    pub fn register_event_with_capacity(
        &self,
        guild_id: &str,
        event_id: &str,
        user_id: &str,
        capacity: Option<u64>,
    ) -> Result<Option<String>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let tx = conn.unchecked_transaction()?;
        let exists: Option<String> = tx
            .query_row(
                "SELECT status FROM event_registrations WHERE guild_id=?1 AND event_id=?2 AND user_id=?3",
                params![guild_id, event_id, user_id],
                |row| row.get(0),
            )
            .optional()?;
        if exists.is_some() {
            return Ok(None);
        }
        let registered: u64 = tx
            .query_row(
                "SELECT COUNT(*) FROM event_registrations WHERE guild_id=?1 AND event_id=?2 AND status IN ('registered','checked_in')",
                params![guild_id, event_id],
                |row| row.get::<_, i64>(0),
            )?
            .try_into()
            .unwrap_or(u64::MAX);
        let status = if capacity.is_some_and(|limit| limit > 0 && registered >= limit) {
            "waitlisted"
        } else {
            "registered"
        };
        tx.execute(
            "INSERT INTO event_registrations(guild_id,event_id,user_id,status,created_at,checked_in_at) VALUES(?1,?2,?3,?4,?5,NULL)",
            params![guild_id, event_id, user_id, status, Utc::now().timestamp_millis()],
        )?;
        tx.commit()?;
        Ok(Some(status.to_string()))
    }

    pub fn remove_event_registration(
        &self,
        guild_id: &str,
        event_id: &str,
        user_id: &str,
    ) -> Result<(bool, Option<String>)> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let tx = conn.unchecked_transaction()?;
        let status: Option<String> = tx
            .query_row(
                "SELECT status FROM event_registrations WHERE guild_id=?1 AND event_id=?2 AND user_id=?3",
                params![guild_id, event_id, user_id],
                |row| row.get(0),
            )
            .optional()?;
        let Some(status) = status else {
            return Ok((false, None));
        };
        tx.execute(
            "DELETE FROM event_registrations WHERE guild_id=?1 AND event_id=?2 AND user_id=?3",
            params![guild_id, event_id, user_id],
        )?;
        let promoted = if status == "registered" || status == "checked_in" {
            let next: Option<(i64, String)> = tx
                .query_row(
                    "SELECT rowid,user_id FROM event_registrations WHERE guild_id=?1 AND event_id=?2 AND status='waitlisted' ORDER BY created_at ASC,rowid ASC LIMIT 1",
                    params![guild_id, event_id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?;
            if let Some((rowid, user_id)) = next {
                tx.execute(
                    "UPDATE event_registrations SET status='registered' WHERE rowid=?1",
                    [rowid],
                )?;
                Some(user_id)
            } else {
                None
            }
        } else {
            None
        };
        tx.commit()?;
        Ok((true, promoted))
    }

    pub fn event_registration(
        &self,
        guild_id: &str,
        event_id: &str,
        user_id: &str,
    ) -> Result<Option<EventRegistrationRecord>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        Ok(conn
            .query_row(
                "SELECT guild_id,event_id,user_id,status,created_at,checked_in_at FROM event_registrations WHERE guild_id=?1 AND event_id=?2 AND user_id=?3",
                params![guild_id, event_id, user_id],
                |row| {
                    Ok(EventRegistrationRecord {
                        guild_id: row.get(0)?,
                        event_id: row.get(1)?,
                        user_id: row.get(2)?,
                        status: row.get(3)?,
                        created_at: row.get(4)?,
                        checked_in_at: row.get(5)?,
                    })
                },
            )
            .optional()?)
    }

    pub fn tickets_for_guild(&self, guild_id: &str, limit: u32) -> Result<Vec<TicketRecord>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let mut stmt = conn.prepare("SELECT guild_id,opener_id,channel_id,status,claimed_by,category,priority,notes,csat,created_at,closed_at FROM tickets WHERE guild_id=?1 ORDER BY created_at DESC LIMIT ?2")?;
        let rows = stmt.query_map(params![guild_id, i64::from(limit.min(200))], |row| {
            Ok(TicketRecord {
                guild_id: row.get(0)?,
                user_id: row.get(1)?,
                channel_id: row.get(2)?,
                status: row.get(3)?,
                claimed_by: row.get(4)?,
                category: row.get(5)?,
                priority: row.get(6)?,
                notes: row.get(7)?,
                csat: row.get(8)?,
                created_at: row.get(9)?,
                closed_at: row.get(10)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn check_in_event(&self, guild_id: &str, event_id: &str, user_id: &str) -> Result<bool> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        Ok(conn.execute(
            "UPDATE event_registrations SET status='checked_in',checked_in_at=?4 WHERE guild_id=?1 AND event_id=?2 AND user_id=?3 AND status='registered'",
            params![guild_id, event_id, user_id, Utc::now().timestamp_millis()],
        )? > 0)
    }

    pub fn event_registrations(
        &self,
        guild_id: &str,
        event_id: &str,
        limit: u32,
    ) -> Result<Vec<EventRegistrationRecord>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let mut stmt = conn.prepare("SELECT guild_id,event_id,user_id,status,created_at,checked_in_at FROM event_registrations WHERE guild_id=?1 AND event_id=?2 ORDER BY created_at ASC LIMIT ?3")?;
        let rows = stmt.query_map(
            params![guild_id, event_id, i64::from(limit.min(100))],
            |row| {
                Ok(EventRegistrationRecord {
                    guild_id: row.get(0)?,
                    event_id: row.get(1)?,
                    user_id: row.get(2)?,
                    status: row.get(3)?,
                    created_at: row.get(4)?,
                    checked_in_at: row.get(5)?,
                })
            },
        )?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn create_suggestion(&self, guild_id: &str, author_id: &str, content: &str) -> Result<i64> {
        self.create_suggestion_in_channel(guild_id, author_id, content, None)
    }

    pub fn create_suggestion_in_channel(
        &self,
        guild_id: &str,
        author_id: &str,
        content: &str,
        channel_id: Option<&str>,
    ) -> Result<i64> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.execute(
            "INSERT INTO suggestions(guild_id,author_id,content,status,created_at,channel_id) VALUES(?1,?2,?3,'pending',?4,?5)",
            params![guild_id, author_id, content, Utc::now().timestamp_millis(), channel_id],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn delete_unpublished_suggestion(&self, guild_id: &str, id: i64) -> Result<bool> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        Ok(conn.execute(
            "DELETE FROM suggestions WHERE guild_id=?1 AND id=?2 AND message_id IS NULL",
            params![guild_id, id],
        )? > 0)
    }

    /// Return the creation time of the latest suggestion submitted by a
    /// member in a guild.  Keeping this query in the store makes cooldown
    /// checks atomic with the same source of truth used for moderation and
    /// privacy exports.
    pub fn latest_suggestion_created_at(
        &self,
        guild_id: &str,
        author_id: &str,
    ) -> Result<Option<i64>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        Ok(conn
            .query_row(
                "SELECT created_at FROM suggestions WHERE guild_id=?1 AND author_id=?2 ORDER BY created_at DESC, id DESC LIMIT 1",
                params![guild_id, author_id],
                |row| row.get(0),
            )
            .optional()?)
    }

    pub fn set_suggestion_message(&self, id: i64, message_id: &str) -> Result<()> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.execute(
            "UPDATE suggestions SET message_id=?2 WHERE id=?1",
            params![id, message_id],
        )?;
        Ok(())
    }

    pub fn suggestion(&self, id: i64) -> Result<Option<SuggestionRecord>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        Ok(conn.query_row(
            "SELECT id,guild_id,author_id,content,message_id,status,created_at,channel_id FROM suggestions WHERE id=?1",
            [id],
            |row| Ok(SuggestionRecord {
                id: row.get(0)?, guild_id: row.get(1)?, author_id: row.get(2)?,
                content: row.get(3)?, message_id: row.get(4)?, status: row.get(5)?, created_at: row.get(6)?, channel_id: row.get(7)?,
            }),
        ).optional()?)
    }

    pub fn set_suggestion_status(&self, guild_id: &str, id: i64, status: &str) -> Result<bool> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        Ok(conn.execute(
            "UPDATE suggestions SET status=?3 WHERE id=?1 AND guild_id=?2",
            params![id, guild_id, status],
        )? > 0)
    }

    pub fn vote_suggestion(&self, id: i64, user_id: &str, vote: i32) -> Result<()> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.execute(
            "INSERT INTO suggestion_votes(suggestion_id,user_id,vote) VALUES(?1,?2,?3) ON CONFLICT(suggestion_id,user_id) DO UPDATE SET vote=excluded.vote",
            params![id, user_id, vote.clamp(-1, 1)],
        )?;
        Ok(())
    }

    pub fn suggestion_votes(&self, id: i64) -> Result<(i64, i64)> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let mut stmt = conn.prepare("SELECT COALESCE(SUM(vote=1),0),COALESCE(SUM(vote=-1),0) FROM suggestion_votes WHERE suggestion_id=?1")?;
        Ok(stmt.query_row([id], |row| Ok((row.get(0)?, row.get(1)?)))?)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_giveaway(
        &self,
        guild_id: &str,
        channel_id: &str,
        prize: &str,
        winners: i64,
        end_at: i64,
        required_role_id: Option<&str>,
        host_id: &str,
    ) -> Result<i64> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.execute(
            "INSERT INTO giveaways(guild_id,channel_id,prize,winners,end_at,required_role_id,host_id,created_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
            params![guild_id, channel_id, prize, winners.clamp(1, 20), end_at, required_role_id, host_id, Utc::now().timestamp_millis()],
        )?;
        Ok(conn.last_insert_rowid())
    }

    /// Persist the giveaway and its end job together, before publishing the panel.
    #[allow(clippy::too_many_arguments)]
    pub fn create_scheduled_giveaway(
        &self,
        guild_id: &str,
        channel_id: &str,
        prize: &str,
        winners: i64,
        end_at: i64,
        required_role_id: Option<&str>,
        host_id: &str,
    ) -> Result<i64> {
        let mut conn = self.conn.lock().expect("store mutex poisoned");
        let tx = conn.transaction()?;
        tx.execute(
            "INSERT INTO giveaways(guild_id,channel_id,prize,winners,end_at,required_role_id,host_id,created_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
            params![guild_id, channel_id, prize, winners.clamp(1, 20), end_at, required_role_id, host_id, Utc::now().timestamp_millis()],
        )?;
        let id = tx.last_insert_rowid();
        let target_id = id.to_string();
        let payload = serde_json::json!({"channel_id": channel_id, "giveaway_id": id}).to_string();
        tx.execute(
            "INSERT INTO scheduled_actions(guild_id,type,target_id,execute_at,payload,case_id) VALUES(?1,'giveaway_end',?2,?3,?4,NULL)",
            params![guild_id, target_id, end_at, payload],
        )?;
        tx.commit()?;
        Ok(id)
    }

    /// Roll back a draft only if no Discord panel was recorded for it.
    pub fn delete_unpublished_giveaway(&self, guild_id: &str, id: i64) -> Result<bool> {
        let mut conn = self.conn.lock().expect("store mutex poisoned");
        let tx = conn.transaction()?;
        let deleted = tx.execute(
            "DELETE FROM giveaways WHERE id=?1 AND guild_id=?2 AND message_id IS NULL",
            params![id, guild_id],
        )? > 0;
        if deleted {
            tx.execute("DELETE FROM giveaway_entries WHERE giveaway_id=?1", [id])?;
            tx.execute("DELETE FROM giveaway_results WHERE giveaway_id=?1", [id])?;
            tx.execute(
                "DELETE FROM scheduled_actions WHERE guild_id=?1 AND type='giveaway_end' AND target_id=?2",
                params![guild_id, id.to_string()],
            )?;
        }
        tx.commit()?;
        Ok(deleted)
    }

    pub fn set_giveaway_message(&self, id: i64, message_id: &str) -> Result<()> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.execute(
            "UPDATE giveaways SET message_id=?2 WHERE id=?1",
            params![id, message_id],
        )?;
        Ok(())
    }

    pub fn giveaway(&self, id: i64) -> Result<Option<GiveawayRecord>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        Ok(conn.query_row(
            "SELECT id,guild_id,channel_id,message_id,prize,winners,end_at,ended,required_role_id,host_id,created_at FROM giveaways WHERE id=?1",
            [id],
            |row| Ok(GiveawayRecord {
                id: row.get(0)?, guild_id: row.get(1)?, channel_id: row.get(2)?, message_id: row.get(3)?,
                prize: row.get(4)?, winners: row.get(5)?, end_at: row.get(6)?, ended: row.get::<_, i64>(7)? != 0,
                required_role_id: row.get(8)?, host_id: row.get(9)?, created_at: row.get(10)?,
            }),
        ).optional()?)
    }

    pub fn active_giveaways(&self, guild_id: &str, limit: u32) -> Result<Vec<GiveawayRecord>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let mut stmt = conn.prepare("SELECT id,guild_id,channel_id,message_id,prize,winners,end_at,ended,required_role_id,host_id,created_at FROM giveaways WHERE guild_id=?1 AND ended=0 ORDER BY end_at LIMIT ?2")?;
        let rows = stmt.query_map(params![guild_id, i64::from(limit.min(50))], |row| {
            Ok(GiveawayRecord {
                id: row.get(0)?,
                guild_id: row.get(1)?,
                channel_id: row.get(2)?,
                message_id: row.get(3)?,
                prize: row.get(4)?,
                winners: row.get(5)?,
                end_at: row.get(6)?,
                ended: row.get::<_, i64>(7)? != 0,
                required_role_id: row.get(8)?,
                host_id: row.get(9)?,
                created_at: row.get(10)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn end_giveaway(&self, id: i64) -> Result<bool> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        Ok(conn.execute("UPDATE giveaways SET ended=1 WHERE id=?1 AND ended=0", [id])? > 0)
    }

    /// Freeze a draw once; retries reuse its winners until announcement succeeds.
    pub fn prepare_giveaway_result(
        &self,
        guild_id: &str,
        id: i64,
    ) -> Result<Option<(Vec<String>, i64)>> {
        let mut conn = self.conn.lock().expect("store mutex poisoned");
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let claim_at = Utc::now().timestamp_millis();
        let found: Option<(bool, i64)> = tx
            .query_row(
                "SELECT ended,winners FROM giveaways WHERE id=?1 AND guild_id=?2",
                params![id, guild_id],
                |row| Ok((row.get::<_, i64>(0)? != 0, row.get(1)?)),
            )
            .optional()?;
        let Some((ended, winner_count)) = found else {
            return Ok(None);
        };
        let existing: Option<(String, bool)> = tx
            .query_row(
                "SELECT winners_json,announced FROM giveaway_results WHERE giveaway_id=?1",
                [id],
                |row| Ok((row.get(0)?, row.get::<_, i64>(1)? != 0)),
            )
            .optional()?;
        if let Some((raw, announced)) = existing {
            if announced {
                return Ok(None);
            }
            let claimed = tx.execute(
                "UPDATE giveaway_results SET claimed_at=?2 WHERE giveaway_id=?1 AND announced=0 AND (claimed_at IS NULL OR claimed_at<?3)",
                params![id, claim_at, claim_at - 15 * 60_000],
            )? > 0;
            if !claimed {
                anyhow::bail!("giveaway announcement already in progress");
            }
            tx.commit()?;
            return Ok(Some((serde_json::from_str(&raw)?, claim_at)));
        }
        if ended {
            return Ok(None);
        }
        let winners = {
            let mut statement = tx.prepare(
                "SELECT user_id FROM giveaway_entries WHERE giveaway_id=?1 ORDER BY RANDOM() LIMIT ?2",
            )?;
            let rows = statement.query_map(params![id, winner_count], |row| row.get(0))?;
            rows.collect::<rusqlite::Result<Vec<String>>>()?
        };
        tx.execute("UPDATE giveaways SET ended=1 WHERE id=?1", [id])?;
        tx.execute(
            "INSERT INTO giveaway_results(giveaway_id,winners_json,claimed_at) VALUES(?1,?2,?3)",
            params![id, serde_json::to_string(&winners)?, claim_at],
        )?;
        tx.commit()?;
        Ok(Some((winners, claim_at)))
    }

    pub fn mark_giveaway_announced(&self, id: i64, claim_at: i64) -> Result<()> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        if conn.execute(
            "UPDATE giveaway_results SET announced=1,claimed_at=NULL WHERE giveaway_id=?1 AND claimed_at=?2 AND announced=0",
            params![id, claim_at],
        )? == 0 {
            anyhow::bail!("giveaway announcement claim was lost");
        }
        Ok(())
    }

    pub fn release_giveaway_claim(&self, id: i64, claim_at: i64) -> Result<()> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.execute(
            "UPDATE giveaway_results SET claimed_at=NULL WHERE giveaway_id=?1 AND claimed_at=?2 AND announced=0",
            params![id, claim_at],
        )?;
        Ok(())
    }

    pub fn add_giveaway_entry(&self, id: i64, user_id: &str) -> Result<bool> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        Ok(conn.execute(
            "INSERT OR IGNORE INTO giveaway_entries(giveaway_id,user_id)
             SELECT id,?2 FROM giveaways WHERE id=?1 AND ended=0 AND end_at>?3",
            params![id, user_id, Utc::now().timestamp_millis()],
        )? > 0)
    }

    pub fn remove_giveaway_entry(&self, id: i64, user_id: &str) -> Result<()> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.execute(
            "DELETE FROM giveaway_entries WHERE giveaway_id=?1 AND user_id=?2
             AND EXISTS(SELECT 1 FROM giveaways WHERE id=?1 AND ended=0 AND end_at>?3)",
            params![id, user_id, Utc::now().timestamp_millis()],
        )?;
        Ok(())
    }

    /// Some(true) joined, Some(false) left, None no longer open.
    /// Keep the deadline check and toggle in one transaction, including across
    /// connections, so a closing worker cannot draw from a changing entry set.
    pub fn toggle_giveaway_entry(&self, id: i64, user_id: &str) -> Result<Option<bool>> {
        let mut conn = self.conn.lock().expect("store mutex poisoned");
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let open: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM giveaways WHERE id=?1 AND ended=0 AND end_at>?2)",
            params![id, Utc::now().timestamp_millis()],
            |row| row.get(0),
        )?;
        if !open {
            return Ok(None);
        }
        let removed = tx.execute(
            "DELETE FROM giveaway_entries WHERE giveaway_id=?1 AND user_id=?2",
            params![id, user_id],
        )? > 0;
        if !removed {
            tx.execute(
                "INSERT INTO giveaway_entries(giveaway_id,user_id) VALUES(?1,?2)",
                params![id, user_id],
            )?;
        }
        tx.commit()?;
        Ok(Some(!removed))
    }

    pub fn giveaway_participant_count(&self, id: i64) -> Result<u64> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        Ok(conn.query_row(
            "SELECT COUNT(*) FROM giveaway_entries WHERE giveaway_id=?1",
            [id],
            |row| row.get::<_, i64>(0).map(|count| count as u64),
        )?)
    }

    pub fn giveaway_entries(&self, id: i64) -> Result<Vec<String>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let mut stmt = conn.prepare(
            "SELECT user_id FROM giveaway_entries WHERE giveaway_id=?1 ORDER BY user_id",
        )?;
        let rows = stmt.query_map([id], |row| row.get(0))?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn star_entry(&self, guild_id: &str, original_id: &str) -> Result<Option<StarEntry>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        Ok(conn.query_row("SELECT starboard_message_id,star_count FROM starboard WHERE guild_id=?1 AND original_message_id=?2", params![guild_id, original_id], |row| Ok(StarEntry { starboard_message_id: row.get(0)?, star_count: row.get(1)? })).optional()?)
    }

    pub fn upsert_star_entry(
        &self,
        guild_id: &str,
        original_id: &str,
        board_message_id: &str,
        count: i64,
    ) -> Result<()> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.execute("INSERT INTO starboard(guild_id,original_message_id,starboard_message_id,star_count) VALUES(?1,?2,?3,?4) ON CONFLICT(guild_id,original_message_id) DO UPDATE SET starboard_message_id=excluded.starboard_message_id,star_count=excluded.star_count", params![guild_id, original_id, board_message_id, count])?;
        Ok(())
    }

    pub fn delete_star_entry(&self, guild_id: &str, original_id: &str) -> Result<()> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.execute(
            "DELETE FROM starboard WHERE guild_id=?1 AND original_message_id=?2",
            params![guild_id, original_id],
        )?;
        Ok(())
    }

    pub fn create_poll(
        &self,
        guild_id: &str,
        channel_id: &str,
        question: &str,
        options: &[String],
        end_at: i64,
    ) -> Result<i64> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.execute("INSERT INTO polls(guild_id,channel_id,question,options,end_at,created_at) VALUES(?1,?2,?3,?4,?5,?6)", params![guild_id, channel_id, question, serde_json::to_string(options)?, end_at, Utc::now().timestamp_millis()])?;
        Ok(conn.last_insert_rowid())
    }

    pub fn set_poll_message(&self, id: i64, message_id: &str) -> Result<()> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.execute(
            "UPDATE polls SET message_id=?2 WHERE id=?1",
            params![id, message_id],
        )?;
        Ok(())
    }

    /// Create the poll and its closing job atomically, before sending the panel.
    pub fn create_scheduled_poll(
        &self,
        guild_id: &str,
        channel_id: &str,
        question: &str,
        options: &[String],
        end_at: i64,
    ) -> Result<i64> {
        let mut conn = self.conn.lock().expect("store mutex poisoned");
        let tx = conn.transaction()?;
        tx.execute("INSERT INTO polls(guild_id,channel_id,question,options,end_at,created_at) VALUES(?1,?2,?3,?4,?5,?6)", params![guild_id, channel_id, question, serde_json::to_string(options)?, end_at, Utc::now().timestamp_millis()])?;
        let id = tx.last_insert_rowid();
        let payload = serde_json::json!({"channel_id": channel_id, "poll_id": id}).to_string();
        tx.execute(
            "INSERT INTO scheduled_actions(guild_id,type,target_id,execute_at,payload,case_id) VALUES(?1,'poll_end',?2,?3,?4,NULL)",
            params![guild_id, id.to_string(), end_at, payload],
        )?;
        tx.commit()?;
        Ok(id)
    }

    /// Remove only this guild's draft; published polls must remain intact.
    pub fn delete_unpublished_poll(&self, guild_id: &str, id: i64) -> Result<bool> {
        let mut conn = self.conn.lock().expect("store mutex poisoned");
        let tx = conn.transaction()?;
        let deleted = tx.execute(
            "DELETE FROM polls WHERE id=?1 AND guild_id=?2 AND message_id IS NULL",
            params![id, guild_id],
        )? > 0;
        if deleted {
            tx.execute("DELETE FROM poll_votes WHERE poll_id=?1", [id])?;
            tx.execute(
                "DELETE FROM scheduled_actions WHERE guild_id=?1 AND type='poll_end' AND target_id=?2",
                params![guild_id, id.to_string()],
            )?;
        }
        tx.commit()?;
        Ok(deleted)
    }

    pub fn poll(&self, id: i64) -> Result<Option<PollRecord>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        Ok(conn.query_row("SELECT id,guild_id,channel_id,message_id,question,options,end_at,closed,created_at FROM polls WHERE id=?1", [id], |row| {
            let options: String = row.get(5)?;
            Ok(PollRecord { id: row.get(0)?, guild_id: row.get(1)?, channel_id: row.get(2)?, message_id: row.get(3)?, question: row.get(4)?, options: serde_json::from_str(&options).unwrap_or_default(), end_at: row.get(6)?, closed: row.get::<_, i64>(7)? != 0, created_at: row.get(8)? })
        }).optional()?)
    }

    pub fn vote_poll(&self, id: i64, user_id: &str, choice: usize) -> Result<bool> {
        let Ok(choice) = i64::try_from(choice) else {
            return Ok(false);
        };
        let conn = self.conn.lock().expect("store mutex poisoned");
        Ok(conn.execute(
            "INSERT INTO poll_votes(poll_id,user_id,choice)
             SELECT id,?2,?3 FROM polls
             WHERE id=?1 AND closed=0 AND end_at>?4 AND ?3<json_array_length(options)
             ON CONFLICT(poll_id,user_id) DO UPDATE SET choice=excluded.choice",
            params![id, user_id, choice, Utc::now().timestamp_millis()],
        )? > 0)
    }

    pub fn poll_counts(&self, id: i64, choices: usize) -> Result<Vec<i64>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let mut counts = vec![0_i64; choices];
        let mut stmt = conn
            .prepare("SELECT choice,COUNT(*) FROM poll_votes WHERE poll_id=?1 GROUP BY choice")?;
        let rows = stmt.query_map([id], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
        })?;
        for row in rows {
            let (choice, count) = row?;
            if let Some(slot) = counts.get_mut(choice.max(0) as usize) {
                *slot = count;
            }
        }
        Ok(counts)
    }

    pub fn close_poll(&self, id: i64) -> Result<bool> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        Ok(conn.execute("UPDATE polls SET closed=1 WHERE id=?1 AND closed=0", [id])? > 0)
    }

    pub fn create_workflow(
        &self,
        guild_id: &str,
        name: &str,
        trigger: &str,
        condition: &str,
        action: &str,
        payload: &str,
    ) -> Result<i64> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.execute("INSERT INTO workflows(guild_id,name,trigger,condition,action,payload,created_at) VALUES(?1,?2,?3,?4,?5,?6,?7)", params![guild_id, name, trigger, condition, action, payload, Utc::now().timestamp_millis()])?;
        Ok(conn.last_insert_rowid())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_workflow_bounded(
        &self,
        guild_id: &str,
        name: &str,
        trigger: &str,
        condition: &str,
        action: &str,
        payload: &str,
        limit: u64,
    ) -> Result<Option<i64>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let tx = conn.unchecked_transaction()?;
        let count: u64 = tx
            .query_row(
                "SELECT COUNT(*) FROM workflows WHERE guild_id=?1",
                [guild_id],
                |row| row.get::<_, i64>(0),
            )?
            .try_into()
            .unwrap_or(u64::MAX);
        if count >= limit {
            return Ok(None);
        }
        tx.execute(
            "INSERT INTO workflows(guild_id,name,trigger,condition,action,payload,created_at) VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![guild_id, name, trigger, condition, action, payload, Utc::now().timestamp_millis()],
        )?;
        let id = tx.last_insert_rowid();
        tx.commit()?;
        Ok(Some(id))
    }

    pub fn workflows(&self, guild_id: &str, limit: u32) -> Result<Vec<WorkflowRecord>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let mut stmt = conn.prepare("SELECT id,guild_id,name,trigger,condition,action,payload,enabled,created_at FROM workflows WHERE guild_id=?1 ORDER BY id DESC LIMIT ?2")?;
        let rows = stmt.query_map(params![guild_id, i64::from(limit.min(100))], |row| {
            Ok(WorkflowRecord {
                id: row.get(0)?,
                guild_id: row.get(1)?,
                name: row.get(2)?,
                trigger: row.get(3)?,
                condition: row.get(4)?,
                action: row.get(5)?,
                payload: row.get(6)?,
                enabled: row.get::<_, i64>(7)? != 0,
                created_at: row.get(8)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn active_workflows(&self, guild_id: &str, trigger: &str) -> Result<Vec<WorkflowRecord>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let mut stmt = conn.prepare("SELECT id,guild_id,name,trigger,condition,action,payload,enabled,created_at FROM workflows WHERE guild_id=?1 AND trigger=?2 AND enabled=1 ORDER BY id LIMIT 25")?;
        let rows = stmt.query_map(params![guild_id, trigger], |row| {
            Ok(WorkflowRecord {
                id: row.get(0)?,
                guild_id: row.get(1)?,
                name: row.get(2)?,
                trigger: row.get(3)?,
                condition: row.get(4)?,
                action: row.get(5)?,
                payload: row.get(6)?,
                enabled: row.get::<_, i64>(7)? != 0,
                created_at: row.get(8)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn workflow(&self, guild_id: &str, id: i64) -> Result<Option<WorkflowRecord>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        Ok(conn
            .query_row(
                "SELECT id,guild_id,name,trigger,condition,action,payload,enabled,created_at FROM workflows WHERE guild_id=?1 AND id=?2",
                params![guild_id, id],
                |row| {
                    Ok(WorkflowRecord {
                        id: row.get(0)?,
                        guild_id: row.get(1)?,
                        name: row.get(2)?,
                        trigger: row.get(3)?,
                        condition: row.get(4)?,
                        action: row.get(5)?,
                        payload: row.get(6)?,
                        enabled: row.get::<_, i64>(7)? != 0,
                        created_at: row.get(8)?,
                    })
                },
            )
            .optional()?)
    }

    pub fn set_workflow_enabled(&self, guild_id: &str, id: i64, enabled: bool) -> Result<bool> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        Ok(conn.execute(
            "UPDATE workflows SET enabled=?3 WHERE guild_id=?1 AND id=?2",
            params![guild_id, id, i64::from(enabled)],
        )? > 0)
    }

    pub fn delete_workflow(&self, guild_id: &str, id: i64) -> Result<bool> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        Ok(conn.execute(
            "DELETE FROM workflows WHERE guild_id=?1 AND id=?2",
            params![guild_id, id],
        )? > 0)
    }

    pub fn record_workflow_run(
        &self,
        workflow_id: i64,
        guild_id: &str,
        source_id: &str,
    ) -> Result<bool> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        Ok(conn.execute("INSERT INTO workflow_runs(workflow_id,guild_id,source_id,created_at) SELECT ?1,?2,?3,?4 WHERE NOT EXISTS (SELECT 1 FROM workflow_runs WHERE workflow_id=?1 AND guild_id=?2 AND source_id=?3)", params![workflow_id, guild_id, source_id, Utc::now().timestamp_millis()])? > 0)
    }

    /// Capture the original roles once; repeated commands must not overwrite them.
    pub fn begin_quarantine(
        &self,
        guild_id: &str,
        user_id: &str,
        role_ids: &[String],
        reason: &str,
    ) -> Result<bool> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        Ok(conn.execute(
            "INSERT OR IGNORE INTO quarantine(guild_id,user_id,role_ids,reason,created_at) VALUES(?1,?2,?3,?4,?5)",
            params![guild_id, user_id, serde_json::to_string(role_ids)?, reason, Utc::now().timestamp_millis()],
        )? > 0)
    }

    pub fn save_quarantine(
        &self,
        guild_id: &str,
        user_id: &str,
        role_ids: &[String],
        reason: &str,
    ) -> Result<()> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.execute("INSERT INTO quarantine(guild_id,user_id,role_ids,reason,created_at) VALUES(?1,?2,?3,?4,?5) ON CONFLICT(guild_id,user_id) DO UPDATE SET role_ids=excluded.role_ids,reason=excluded.reason,created_at=excluded.created_at", params![guild_id, user_id, serde_json::to_string(role_ids)?, reason, Utc::now().timestamp_millis()])?;
        Ok(())
    }

    pub fn get_quarantine(
        &self,
        guild_id: &str,
        user_id: &str,
    ) -> Result<Option<QuarantineRecord>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        Ok(conn.query_row("SELECT guild_id,user_id,role_ids,reason,created_at FROM quarantine WHERE guild_id=?1 AND user_id=?2", params![guild_id, user_id], |row| {
            let raw: String = row.get(2)?;
            Ok(QuarantineRecord { guild_id: row.get(0)?, user_id: row.get(1)?, role_ids: serde_json::from_str(&raw).unwrap_or_default(), reason: row.get(3)?, created_at: row.get(4)? })
        }).optional()?)
    }

    pub fn clear_quarantine(&self, guild_id: &str, user_id: &str) -> Result<bool> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        Ok(conn.execute(
            "DELETE FROM quarantine WHERE guild_id=?1 AND user_id=?2",
            params![guild_id, user_id],
        )? > 0)
    }
}

fn parse_dt(value: &str) -> Result<DateTime<Utc>> {
    Ok(DateTime::parse_from_rfc3339(value)?.with_timezone(&Utc))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeated_quarantine_keeps_the_original_roles_and_guild_scope() {
        let store = Store::open(":memory:").unwrap();
        assert!(
            store
                .begin_quarantine("g", "u", &["10".into(), "20".into()], "original")
                .unwrap()
        );
        assert!(!store.begin_quarantine("g", "u", &[], "repeated").unwrap());
        let saved = store.get_quarantine("g", "u").unwrap().unwrap();
        assert_eq!(saved.role_ids, vec!["10", "20"]);
        assert_eq!(saved.reason, "original");
        assert!(
            store
                .begin_quarantine("other", "u", &["30".into()], "other")
                .unwrap()
        );
        assert_eq!(
            store
                .get_quarantine("other", "u")
                .unwrap()
                .unwrap()
                .role_ids,
            vec!["30"]
        );
    }

    #[test]
    fn failed_closing_job_creation_rolls_back_the_event() {
        let store = Store::open(":memory:").unwrap();
        {
            let conn = store.conn.lock().unwrap();
            conn.execute_batch("CREATE TRIGGER reject_job BEFORE INSERT ON scheduled_actions BEGIN SELECT RAISE(ABORT,'test job failure'); END;").unwrap();
        }
        assert!(
            store
                .create_scheduled_poll("g", "10", "Question", &["Yes".into(), "No".into()], 0)
                .is_err()
        );
        assert!(
            store
                .create_scheduled_giveaway("g", "10", "Prize", 1, 0, None, "host")
                .is_err()
        );
        let conn = store.conn.lock().unwrap();
        for table in ["polls", "giveaways", "scheduled_actions"] {
            assert_eq!(
                conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| row
                    .get::<_, i64>(0))
                    .unwrap(),
                0
            );
        }
    }

    #[test]
    fn poll_draft_and_closing_job_have_one_lifecycle() {
        let store = Store::open(":memory:").unwrap();
        let choices = ["Yes".into(), "No".into()];
        let draft = store
            .create_scheduled_poll("g", "c", "Question", &choices, 123_456)
            .unwrap();
        let jobs = store.due_scheduled_actions(123_456, 10).unwrap();
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].2, "poll_end");
        assert_eq!(jobs[0].3, draft.to_string());
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&jobs[0].4).unwrap()["poll_id"],
            draft
        );
        assert!(!store.delete_unpublished_poll("other", draft).unwrap());
        assert!(store.poll(draft).unwrap().is_some());
        assert!(store.delete_unpublished_poll("g", draft).unwrap());
        assert!(store.poll(draft).unwrap().is_none());
        assert!(store.due_scheduled_actions(123_456, 10).unwrap().is_empty());
        let published = store
            .create_scheduled_poll("g", "c", "Question", &choices, 123_456)
            .unwrap();
        store.set_poll_message(published, "123").unwrap();
        assert!(!store.delete_unpublished_poll("g", published).unwrap());
        assert_eq!(store.due_scheduled_actions(123_456, 10).unwrap().len(), 1);
    }

    #[test]
    fn giveaway_draft_and_end_job_are_created_and_removed_together() {
        let store = Store::open(":memory:").unwrap();
        let id = store
            .create_scheduled_giveaway("g", "c", "Prémio", 2, 123_456, None, "host")
            .unwrap();
        let due = store.due_scheduled_actions(123_456, 10).unwrap();
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].2, "giveaway_end");
        assert_eq!(due[0].3, id.to_string());
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&due[0].4).unwrap()["giveaway_id"],
            id
        );
        // The deadline worker may have frozen a result before a slow panel
        // publication fails. Removing the draft must also remove that result.
        store.prepare_giveaway_result("g", id).unwrap().unwrap();
        assert!(store.delete_unpublished_giveaway("g", id).unwrap());
        assert!(store.giveaway(id).unwrap().is_none());
        assert!(store.due_scheduled_actions(123_456, 10).unwrap().is_empty());
        assert_eq!(
            store
                .conn
                .lock()
                .unwrap()
                .query_row(
                    "SELECT COUNT(*) FROM giveaway_results WHERE giveaway_id=?1",
                    [id],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
            0
        );

        let published = store
            .create_scheduled_giveaway("g", "c", "Prémio", 2, 123_456, None, "host")
            .unwrap();
        store.set_giveaway_message(published, "123").unwrap();
        assert!(!store.delete_unpublished_giveaway("g", published).unwrap());
        assert!(store.giveaway(published).unwrap().is_some());
        assert_eq!(store.due_scheduled_actions(123_456, 10).unwrap().len(), 1);
    }

    #[test]
    fn giveaway_result_is_frozen_until_announcement() {
        let store = Store::open(":memory:").unwrap();
        let id = store
            .create_scheduled_giveaway("g", "c", "Prize", 1, i64::MAX, None, "host")
            .unwrap();
        store.add_giveaway_entry(id, "first").unwrap();
        assert_eq!(store.prepare_giveaway_result("other", id).unwrap(), None);
        let (selected, first_claim) = store.prepare_giveaway_result("g", id).unwrap().unwrap();
        assert_eq!(selected, vec!["first"]);
        assert_eq!(store.toggle_giveaway_entry(id, "late").unwrap(), None);
        assert!(store.prepare_giveaway_result("g", id).is_err());
        store.release_giveaway_claim(id, first_claim).unwrap();
        let (retry, retry_claim) = store.prepare_giveaway_result("g", id).unwrap().unwrap();
        assert_eq!(retry, selected);
        store.mark_giveaway_announced(id, retry_claim).unwrap();
        assert_eq!(store.prepare_giveaway_result("g", id).unwrap(), None);
    }

    #[test]
    fn giveaway_entries_cannot_change_after_close() {
        let store = Store::open(":memory:").unwrap();
        let id = store
            .create_giveaway("g", "c", "Prize", 1, i64::MAX, None, "host")
            .unwrap();
        assert!(store.add_giveaway_entry(id, "first").unwrap());
        // A handler may have read the open record before another worker closes it.
        assert!(store.end_giveaway(id).unwrap());
        assert!(!store.add_giveaway_entry(id, "late").unwrap());
        store.remove_giveaway_entry(id, "first").unwrap();
        assert_eq!(store.giveaway_entries(id).unwrap(), vec!["first"]);
    }

    #[test]
    fn giveaway_entries_cannot_change_after_deadline_or_for_missing_event() {
        let store = Store::open(":memory:").unwrap();
        let id = store
            .create_giveaway("g", "c", "Prize", 1, 0, None, "host")
            .unwrap();
        assert!(!store.add_giveaway_entry(id, "late").unwrap());
        assert!(!store.add_giveaway_entry(id + 1, "missing").unwrap());
        assert!(store.giveaway_entries(id).unwrap().is_empty());
    }

    #[test]
    fn poll_votes_cannot_change_after_close() {
        let store = Store::open(":memory:").unwrap();
        let id = store
            .create_poll("g", "c", "Choose", &["A".into(), "B".into()], i64::MAX)
            .unwrap();
        store.vote_poll(id, "first", 0).unwrap();
        assert!(store.close_poll(id).unwrap());
        store.vote_poll(id, "first", 1).unwrap();
        store.vote_poll(id, "late", 1).unwrap();
        assert_eq!(store.poll_counts(id, 2).unwrap(), vec![1, 0]);
    }

    #[test]
    fn poll_votes_reject_expired_missing_and_invalid_choices() {
        let store = Store::open(":memory:").unwrap();
        let expired = store
            .create_poll("g", "c", "Choose", &["A".into(), "B".into()], 0)
            .unwrap();
        store.vote_poll(expired, "late", 0).unwrap();
        assert_eq!(store.poll_counts(expired, 2).unwrap(), vec![0, 0]);
        let open = store
            .create_poll("g", "c", "Choose", &["A".into(), "B".into()], i64::MAX)
            .unwrap();
        store.vote_poll(open, "first", 0).unwrap();
        store.vote_poll(open, "first", 2).unwrap();
        store.vote_poll(open, "huge", usize::MAX).unwrap();
        store.vote_poll(open + 1, "missing", 0).unwrap();
        assert_eq!(store.poll_counts(open, 2).unwrap(), vec![1, 0]);
        assert_eq!(store.poll_counts(open + 1, 2).unwrap(), vec![0, 0]);
    }

    #[test]
    fn giveaway_participant_count_tracks_unique_entries_and_survives_closure() {
        let store = Store::open(":memory:").unwrap();
        let id = store
            .create_giveaway("g", "c", "Prize", 1, i64::MAX, None, "host")
            .unwrap();
        let other = store
            .create_giveaway("other", "c", "Other", 1, i64::MAX, None, "host")
            .unwrap();
        assert_eq!(store.giveaway_participant_count(id).unwrap(), 0);
        store.toggle_giveaway_entry(id, "a").unwrap();
        store.toggle_giveaway_entry(id, "b").unwrap();
        store.toggle_giveaway_entry(other, "c").unwrap();
        assert_eq!(store.giveaway_participant_count(id).unwrap(), 2);
        store.toggle_giveaway_entry(id, "a").unwrap();
        assert_eq!(store.giveaway_participant_count(id).unwrap(), 1);
        store.end_giveaway(id).unwrap();
        assert_eq!(store.giveaway_participant_count(id).unwrap(), 1);
        assert_eq!(store.giveaway_participant_count(other).unwrap(), 1);
        assert_eq!(store.giveaway_participant_count(other + 1).unwrap(), 0);
    }

    #[test]
    fn giveaway_toggle_is_atomic_and_reports_closed_events() {
        let store = Store::open(":memory:").unwrap();
        let id = store
            .create_giveaway("g", "c", "Prize", 1, i64::MAX, None, "host")
            .unwrap();
        assert_eq!(
            store.toggle_giveaway_entry(id, "member").unwrap(),
            Some(true)
        );
        assert_eq!(
            store.toggle_giveaway_entry(id, "member").unwrap(),
            Some(false)
        );
        assert_eq!(
            store.toggle_giveaway_entry(id, "member").unwrap(),
            Some(true)
        );
        store.end_giveaway(id).unwrap();
        assert_eq!(store.toggle_giveaway_entry(id, "member").unwrap(), None);
        assert_eq!(store.toggle_giveaway_entry(id, "late").unwrap(), None);
        assert_eq!(store.giveaway_entries(id).unwrap(), vec!["member"]);
        let expired = store
            .create_giveaway("g", "c", "Prize", 1, 0, None, "host")
            .unwrap();
        assert_eq!(store.toggle_giveaway_entry(expired, "late").unwrap(), None);
        assert_eq!(
            store.toggle_giveaway_entry(expired + 1, "missing").unwrap(),
            None
        );
    }

    #[test]
    fn simultaneous_giveaway_toggles_do_not_lose_clicks() {
        let store = Store::open(":memory:").unwrap();
        let id = store
            .create_giveaway("g", "c", "Prize", 1, i64::MAX, None, "host")
            .unwrap();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(16));
        let handles: Vec<_> = (0..16)
            .map(|_| {
                let store = store.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    store.toggle_giveaway_entry(id, "member").unwrap()
                })
            })
            .collect();
        let joined = handles
            .into_iter()
            .filter_map(|handle| handle.join().unwrap())
            .filter(|joined| *joined)
            .count();
        assert_eq!(joined, 8);
        assert!(store.giveaway_entries(id).unwrap().is_empty());
    }

    #[test]
    fn open_poll_allows_vote_changes_but_rejects_invalid_writes() {
        let store = Store::open(":memory:").unwrap();
        let id = store
            .create_poll("g", "c", "Choose", &["A".into(), "B".into()], i64::MAX)
            .unwrap();
        assert!(store.vote_poll(id, "member", 0).unwrap());
        assert!(store.vote_poll(id, "member", 1).unwrap());
        assert_eq!(store.poll_counts(id, 2).unwrap(), vec![0, 1]);
        assert!(!store.vote_poll(id, "member", 2).unwrap());
        assert!(!store.vote_poll(id, "member", usize::MAX).unwrap());
        store.close_poll(id).unwrap();
        assert!(!store.vote_poll(id, "member", 0).unwrap());
        assert_eq!(store.poll_counts(id, 2).unwrap(), vec![0, 1]);
    }
    use helper_contracts::{EntitlementSnapshot, Plan, SessionClaims};

    #[test]
    fn schema_and_case_round_trip() {
        let store = Store::open(":memory:").unwrap();
        let id = store
            .record_case("guild", "warn", "user", "mod", "reason", None)
            .unwrap();
        assert_eq!(id, 1);
        let cases = store.recent_cases("guild", 10).unwrap();
        assert_eq!(cases[0].target_id, "user");
        assert_eq!(
            store.cases_for_target("guild", "user", 10).unwrap().len(),
            1
        );
        let audit = store.recent_audit_events("guild", 10).unwrap();
        assert_eq!(audit.len(), 1);
        assert!(!audit[0].correlation_id.is_empty());
        assert_eq!(audit[0].actor_id, "mod");
        assert_eq!(audit[0].reason, "reason");
        assert_eq!(audit[0].outcome, "recorded");
        assert!(serde_json::from_str::<serde_json::Value>(&audit[0].before_json).is_ok());
        assert!(serde_json::from_str::<serde_json::Value>(&audit[0].after_json).is_ok());
        assert!(
            store
                .consume_quota("guild", "user", "workflow_runs", 1, Utc::now())
                .unwrap()
        );
        assert!(
            !store
                .consume_quota("guild", "user", "workflow_runs", 1, Utc::now())
                .unwrap()
        );
    }

    #[test]
    fn leaderboard_query_honors_the_configurable_hundred_member_limit() {
        let store = Store::open(":memory:").unwrap();
        for index in 0..110 {
            store
                .add_xp("guild", &format!("member-{index:03}"), 100)
                .unwrap();
        }
        store.add_xp("other-guild", "outsider", 9999).unwrap();
        let rows = store.top_levels("guild", 100).unwrap();
        assert_eq!(rows.len(), 100);
        assert_eq!(rows[0].user_id, "member-000");
        assert_eq!(rows[99].user_id, "member-099");
        assert!(rows.iter().all(|row| row.guild_id == "guild"));
        assert_eq!(store.top_levels("guild", 10).unwrap().len(), 10);
        assert_eq!(store.top_levels("guild", 1000).unwrap().len(), 100);
        assert!(store.top_levels("guild", 0).unwrap().is_empty());
    }

    #[test]
    fn compare_and_swap_setting_rejects_stale_writes() {
        let store = Store::open(":memory:").unwrap();
        store
            .set_setting("guild", "studio.template.one", "v1")
            .unwrap();

        assert!(
            store
                .compare_and_swap_setting("guild", "studio.template.one", "v1", "v2")
                .unwrap()
        );
        assert_eq!(
            store
                .get_setting("guild", "studio.template.one")
                .unwrap()
                .as_deref(),
            Some("v2")
        );
        assert!(
            !store
                .compare_and_swap_setting("guild", "studio.template.one", "v1", "v3")
                .unwrap()
        );
        assert_eq!(
            store
                .get_setting("guild", "studio.template.one")
                .unwrap()
                .as_deref(),
            Some("v2")
        );
    }

    #[test]
    fn studio_template_revisions_are_guild_scoped_and_ordered() {
        let store = Store::open(":memory:").unwrap();
        store
            .record_studio_template_revision("guild-a", "template", 1, r#"{"version":1}"#, "user-a")
            .unwrap();
        store
            .record_studio_template_revision("guild-a", "template", 2, r#"{"version":2}"#, "user-b")
            .unwrap();
        store
            .record_studio_template_revision("guild-b", "template", 1, r#"{"version":1}"#, "user-c")
            .unwrap();

        let revisions = store
            .studio_template_revisions("guild-a", "template", 50)
            .unwrap();
        assert_eq!(
            revisions
                .iter()
                .map(|item| item.revision)
                .collect::<Vec<_>>(),
            vec![2, 1]
        );
        assert_eq!(revisions[0].created_by, "user-b");
        assert_eq!(
            store
                .studio_template_revision("guild-a", "template", 1)
                .unwrap()
                .unwrap()
                .template_json,
            r#"{"version":1}"#
        );
        assert!(
            store
                .studio_template_revision("guild-a", "template", 3)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            store
                .studio_template_revisions("guild-b", "template", 50)
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn activity_log_is_metadata_only_and_bounded() {
        let store = Store::open(":memory:").unwrap();
        let oversized = "x".repeat(3_000);
        let id = store
            .record_activity(
                "guild",
                "message_edit",
                "user",
                Some("member#0001"),
                Some("user"),
                &oversized,
            )
            .unwrap();
        assert_eq!(id, 1);
        let rows = store.recent_activity("guild", 10).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].kind, "message_edit");
        assert_eq!(rows[0].detail.chars().count(), 2_000);
        assert_eq!(rows[0].user_tag.as_deref(), Some("member#0001"));
    }

    #[test]
    fn oauth_pending_capacity_preserves_existing_flows() {
        let store = Store::open(":memory:").unwrap();
        let now = Utc::now().timestamp();
        {
            let connection = store.conn.lock().unwrap();
            connection.execute(
                "WITH RECURSIVE sequence(value) AS (SELECT 1 UNION ALL SELECT value+1 FROM sequence WHERE value<4096) INSERT INTO helper_oauth_states(state_hash,expires_at,used_at,code_verifier) SELECT 'state-'||value,?1,NULL,'synthetic-verifier' FROM sequence",
                [now+600],
            ).unwrap();
        }
        assert_eq!(
            store
                .register_oauth_state("overflow", now + 600, "new")
                .unwrap_err()
                .to_string(),
            "oauth_pending_limit"
        );
        assert_eq!(
            store
                .consume_oauth_state("state-1", now)
                .unwrap()
                .as_deref(),
            Some("synthetic-verifier")
        );
        store
            .register_oauth_state("after-consumption", now + 600, "new")
            .unwrap();
    }

    #[test]
    fn sessions_revoke_and_entitlements_persist() {
        let store = Store::open(":memory:").unwrap();
        store.register_oauth_state("state", 10, "verifier").unwrap();
        assert_eq!(
            store.consume_oauth_state("state", 10).unwrap().as_deref(),
            Some("verifier")
        );
        assert!(store.consume_oauth_state("state", 10).unwrap().is_none());
        store
            .register_oauth_state("expired", 10, "verifier")
            .unwrap();
        assert!(store.consume_oauth_state("expired", 11).unwrap().is_none());
        let now = Utc::now();
        let claims = SessionClaims {
            session_id: Uuid::new_v4(),
            user_id: "u".into(),
            guild_id: "g".into(),
            issued_at: now,
            expires_at: now + chrono::Duration::hours(1),
            last_seen_at: now,
        };
        store.save_session(&claims).unwrap();
        store
            .replace_session_guilds(
                claims.session_id,
                &[("g".into(), "Guild".into(), Some("8".into()))],
            )
            .unwrap();
        assert_eq!(
            store.session_guilds(claims.session_id).unwrap()[0].name,
            "Guild"
        );
        assert!(store.load_session(claims.session_id).unwrap().is_some());
        store.revoke_session(claims.session_id).unwrap();
        assert!(store.load_session(claims.session_id).unwrap().is_none());
        let mut entitlement = EntitlementSnapshot::free("u");
        entitlement.plan = Plan::Plus;
        store.save_entitlement(&entitlement).unwrap();
        assert_eq!(
            store.load_entitlement("u").unwrap().unwrap().plan,
            Plan::Plus
        );
    }

    #[test]
    fn ticket_claim_cannot_replace_another_staff_member() {
        let store = Store::open(":memory:").unwrap();
        store.open_ticket("guild", "opener", "channel").unwrap();
        assert!(store.claim_ticket("channel", "first-staff").unwrap());
        assert!(store.claim_ticket("channel", "first-staff").unwrap());
        assert!(!store.claim_ticket("channel", "second-staff").unwrap());
        assert_eq!(
            store
                .ticket_by_channel("channel")
                .unwrap()
                .unwrap()
                .claimed_by
                .as_deref(),
            Some("first-staff")
        );
        store.close_ticket("channel").unwrap();
        assert!(!store.claim_ticket("channel", "first-staff").unwrap());
        assert!(!store.claim_ticket("missing", "first-staff").unwrap());
    }

    #[test]
    fn simultaneous_ticket_claims_have_one_owner() {
        let store = Store::open(":memory:").unwrap();
        store.open_ticket("guild", "opener", "channel").unwrap();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
        let handles: Vec<_> = (0..8)
            .map(|index| {
                let store = store.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    store
                        .claim_ticket("channel", &format!("staff-{index}"))
                        .unwrap()
                })
            })
            .collect();
        let winners = handles
            .into_iter()
            .filter_map(|handle| handle.join().unwrap().then_some(()))
            .count();
        assert_eq!(winners, 1);
    }

    #[test]
    fn community_state_and_due_jobs_round_trip() {
        let store = Store::open(":memory:").unwrap();
        store.set_afk("g", "u", "away").unwrap();
        assert_eq!(store.get_afk("g", "u").unwrap().unwrap().reason, "away");
        assert!(store.clear_afk("g", "u").unwrap());
        store.upsert_tag("g", "rules", "be kind", "u").unwrap();
        assert_eq!(
            store.get_tag("g", "rules").unwrap().unwrap().content,
            "be kind"
        );
        let records = store.list_tag_records("g", 10).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].name, "rules");
        assert_eq!(records[0].author_id, "u");
        assert_eq!(store.add_xp("g", "u", 5).unwrap(), 5);
        assert_eq!(store.level_for("g", "u").unwrap(), 5);
        store.add_xp("g", "other", 25).unwrap();
        assert_eq!(store.level_rank("g", "other").unwrap(), Some(1));
        assert_eq!(store.level_rank("g", "u").unwrap(), Some(2));
        assert_eq!(store.level_rank("g", "missing").unwrap(), None);
        assert!(
            store
                .unlock_achievement("g", "u", "first_steps", 100, 10)
                .unwrap()
        );
        assert!(
            !store
                .unlock_achievement("g", "u", "first_steps", 100, 11)
                .unwrap()
        );
        assert!(
            store
                .unlock_achievement("g", "other", "first_steps", 100, 12)
                .unwrap()
        );
        let unlocked = store.achievements_for("g", "u").unwrap();
        assert_eq!(unlocked.len(), 1);
        assert_eq!(unlocked[0].achievement_key, "first_steps");
        assert!(
            store
                .achievements_for("other-guild", "u")
                .unwrap()
                .is_empty()
        );
        assert!(
            store
                .claim_welcome_delivery("g", "u", "guided_channel", 100, 600)
                .unwrap()
        );
        assert!(
            !store
                .claim_welcome_delivery("g", "u", "guided_channel", 101, 600)
                .unwrap()
        );
        assert!(
            store
                .claim_welcome_delivery("g", "u", "guided_channel", 701, 600)
                .unwrap()
        );
        assert!(
            store
                .claim_welcome_delivery("other-guild", "u", "guided_channel", 101, 600)
                .unwrap()
        );
        let id = store
            .schedule("g", "u", 1, r#"{"channel_id":"2","text":"hello"}"#)
            .unwrap();
        let jobs = store.due_scheduled_actions(1, 10).unwrap();
        assert_eq!(jobs[0].0, id);
        assert_eq!(jobs[0].4, r#"{"channel_id":"2","text":"hello"}"#);
        store.delete_scheduled_action(id).unwrap();
        store
            .schedule_typed("g", "event_reminder", "event-1", 2, "{}")
            .unwrap();
        store
            .schedule_typed("g", "event_reminder", "event-2", 2, "{}")
            .unwrap();
        assert_eq!(
            store
                .delete_scheduled_actions_for("g", "event_reminder", "event-1")
                .unwrap(),
            1
        );
        assert_eq!(store.due_scheduled_actions(2, 10).unwrap().len(), 1);
        store.open_ticket("g", "u", "20").unwrap();
        assert_eq!(store.active_ticket_count_for_user("g", "u").unwrap(), 1);
        assert!(!store.try_open_ticket("g", "u", "21", 1).unwrap());
        assert!(store.close_ticket("20").unwrap());
        assert_eq!(store.active_ticket_count_for_user("g", "u").unwrap(), 0);
        assert!(store.try_open_ticket("g", "u", "21", 1).unwrap());
        assert_eq!(
            store.ticket_by_channel("20").unwrap().unwrap().status,
            "closed"
        );
        assert!(store.reopen_ticket("20").unwrap());
        assert_eq!(
            store.ticket_by_channel("20").unwrap().unwrap().status,
            "open"
        );
    }

    #[test]
    fn bounded_settings_are_atomic_and_guild_scoped() {
        let store = Store::open(":memory:").unwrap();
        assert!(
            store
                .insert_setting_bounded(
                    "guild-a",
                    "studio.template.one",
                    "{}",
                    "studio.template.",
                    1
                )
                .unwrap()
        );
        assert!(
            !store
                .insert_setting_bounded(
                    "guild-a",
                    "studio.template.two",
                    "{}",
                    "studio.template.",
                    1
                )
                .unwrap()
        );
        assert!(
            store
                .insert_setting_bounded(
                    "guild-b",
                    "studio.template.two",
                    "{}",
                    "studio.template.",
                    1
                )
                .unwrap()
        );
        assert_eq!(
            store
                .settings_with_prefix("guild-a", "studio.template.")
                .unwrap()
                .len(),
            1
        );
        assert!(
            store
                .delete_setting("guild-a", "studio.template.one")
                .unwrap()
        );
        assert!(
            !store
                .delete_setting("guild-a", "studio.template.one")
                .unwrap()
        );
    }

    #[test]
    fn enabled_feature_settings_are_guild_scoped_and_filter_disabled_rows() {
        let store = Store::open(":memory:").unwrap();
        store
            .publish_feature_setting(
                "guild-a",
                "web3.crypto_stats",
                true,
                r#"{"coinIds":"bitcoin"}"#,
                None,
                "owner-a",
                &[],
            )
            .unwrap();
        store
            .publish_feature_setting(
                "guild-b",
                "web3.crypto_stats",
                false,
                r#"{"coinIds":"ethereum"}"#,
                None,
                "owner-b",
                &[],
            )
            .unwrap();
        let rows = store.enabled_feature_settings("web3.crypto_stats").unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].guild_id, "guild-a");
        assert_eq!(rows[0].config_json, r#"{"coinIds":"bitcoin"}"#);
        let all_rows = store.feature_settings("web3.crypto_stats").unwrap();
        assert_eq!(all_rows.len(), 2);
        assert!(
            all_rows
                .iter()
                .any(|row| row.guild_id == "guild-b" && !row.enabled)
        );
    }

    #[test]
    fn feature_publish_is_revisioned_atomic_and_conflict_safe() {
        let store = Store::open(":memory:").unwrap();
        let first = store
            .publish_feature_setting(
                "guild-a",
                "protection.antispam",
                true,
                r#"{"floodCount":8}"#,
                None,
                "user-a",
                &[
                    ("feature.protection.antispam".into(), "true".into()),
                    ("security.antispam.flood_count".into(), "8".into()),
                ],
            )
            .unwrap();
        assert_eq!(first.revision, 1);
        assert_eq!(
            store
                .get_setting("guild-a", "security.antispam.flood_count")
                .unwrap()
                .as_deref(),
            Some("8")
        );
        let conflict = store.publish_feature_setting(
            "guild-a",
            "protection.antispam",
            false,
            r#"{}"#,
            Some(0),
            "user-b",
            &[],
        );
        assert!(
            conflict
                .unwrap_err()
                .to_string()
                .starts_with("feature_revision_conflict:1")
        );
        let second = store
            .publish_feature_setting(
                "guild-a",
                "protection.antispam",
                false,
                r#"{}"#,
                Some(1),
                "user-b",
                &[("feature.protection.antispam".into(), "false".into())],
            )
            .unwrap();
        assert_eq!(second.revision, 2);
        assert_eq!(
            store
                .feature_revisions("guild-a", "protection.antispam", 10)
                .unwrap()
                .len(),
            2
        );
    }

    #[test]
    fn youtube_feature_publish_keeps_subscription_and_revision_atomic() {
        let store = Store::open(":memory:").unwrap();
        let write = YouTubeSubscriptionWrite {
            source_channel_id: "UC_abc-123".into(),
            target_channel_id: "123456789012345678".into(),
            message_template: "New video: {url}".into(),
            mention: String::new(),
            enabled: true,
            interval_seconds: 300,
            created_by: "user-a".into(),
        };
        let first = store
            .publish_youtube_feature_setting(
                "guild-a",
                "social.youtube",
                true,
                r#"{"sourceChannelId":"UC_abc-123"}"#,
                None,
                "user-a",
                &[],
                Some(&write),
            )
            .unwrap();
        assert_eq!(first.revision, 1);
        assert_eq!(store.youtube_subscriptions("guild-a").unwrap().len(), 1);

        let conflict = store.publish_youtube_feature_setting(
            "guild-a",
            "social.youtube",
            false,
            "{}",
            Some(0),
            "user-b",
            &[],
            Some(&YouTubeSubscriptionWrite {
                enabled: false,
                ..write.clone()
            }),
        );
        assert!(
            conflict
                .unwrap_err()
                .to_string()
                .starts_with("feature_revision_conflict:1")
        );
        assert!(store.youtube_subscriptions("guild-a").unwrap()[0].enabled);

        let changed = store
            .publish_youtube_feature_setting(
                "guild-a",
                "social.youtube",
                true,
                r#"{"sourceChannelId":"UC_changed-456"}"#,
                Some(1),
                "user-b",
                &[],
                Some(&YouTubeSubscriptionWrite {
                    source_channel_id: "UC_changed-456".into(),
                    target_channel_id: "987654321098765432".into(),
                    message_template: "Changed: {url}".into(),
                    mention: "@here".into(),
                    enabled: true,
                    interval_seconds: 600,
                    created_by: "user-b".into(),
                }),
            )
            .unwrap();
        assert_eq!(changed.revision, 2);

        // A rollback is represented by a new revision containing the old
        // payload. The provider-specific publisher must restore both pieces
        // together, rather than leaving the worker on the changed channel.
        let restored = store
            .publish_youtube_feature_setting(
                "guild-a",
                "social.youtube",
                true,
                r#"{"sourceChannelId":"UC_abc-123"}"#,
                Some(2),
                "user-c",
                &[],
                Some(&write),
            )
            .unwrap();
        assert_eq!(restored.revision, 3);
        let subscription = store.youtube_subscriptions("guild-a").unwrap();
        assert_eq!(subscription.len(), 1);
        assert_eq!(subscription[0].source_channel_id, "UC_abc-123");
        assert_eq!(subscription[0].target_channel_id, "123456789012345678");
        assert_eq!(subscription[0].message_template, "New video: {url}");
        assert_eq!(subscription[0].mention, "");
        assert!(subscription[0].enabled);

        let second = store
            .publish_youtube_feature_setting(
                "guild-a",
                "social.youtube",
                false,
                "{}",
                Some(3),
                "user-b",
                &[],
                None,
            )
            .unwrap();
        assert_eq!(second.revision, 4);
        assert!(!store.youtube_subscriptions("guild-a").unwrap()[0].enabled);
    }

    #[test]
    fn provider_feature_disable_without_payload_stops_existing_workers_atomically() {
        let store = Store::open(":memory:").unwrap();

        store
            .create_rss_subscription(
                "guild-rss",
                "https://example.com/feed.xml",
                "123456789012345678",
                "New post: {url}",
                "",
                true,
                300,
                "owner",
            )
            .unwrap();
        store
            .publish_rss_feature_setting(
                "guild-rss",
                "social.rss",
                false,
                "{}",
                None,
                "owner",
                &[],
                None,
            )
            .unwrap();
        assert!(
            store
                .rss_subscriptions("guild-rss")
                .unwrap()
                .iter()
                .all(|row| !row.enabled)
        );

        store
            .create_bluesky_subscription(
                "guild-bluesky",
                "example.com",
                "123456789012345678",
                "New post: {url}",
                "",
                true,
                300,
                "owner",
            )
            .unwrap();
        store
            .publish_bluesky_feature_setting(
                "guild-bluesky",
                "social.bluesky",
                false,
                "{}",
                None,
                "owner",
                &[],
                None,
            )
            .unwrap();
        assert!(
            store
                .bluesky_subscriptions("guild-bluesky")
                .unwrap()
                .iter()
                .all(|row| !row.enabled)
        );

        store
            .create_twitch_subscription(
                "guild-twitch",
                "vozen",
                "123456789",
                "123456789012345678",
                "{url}",
                "",
                true,
                "owner",
            )
            .unwrap();
        store
            .publish_twitch_feature_setting(
                "guild-twitch",
                "social.twitch",
                false,
                "{}",
                None,
                "owner",
                &[],
                None,
            )
            .unwrap();
        assert!(
            store
                .twitch_subscriptions("guild-twitch")
                .unwrap()
                .iter()
                .all(|row| !row.enabled)
        );
    }

    #[test]
    fn reddit_feature_publish_keeps_subscription_and_revision_atomic() {
        let store = Store::open(":memory:").unwrap();
        let write = RedditSubscriptionWrite {
            source_subreddit: "discordapp".into(),
            target_channel_id: "123456789012345678".into(),
            message_template: "New post: {title} {permalink}".into(),
            mention: String::new(),
            enabled: true,
            interval_seconds: 300,
            created_by: "user-a".into(),
        };
        let first = store
            .publish_reddit_feature_setting(
                "guild-a",
                "social.reddit",
                true,
                r#"{"sourceSubreddit":"discordapp"}"#,
                None,
                "user-a",
                &[],
                Some(&write),
            )
            .unwrap();
        assert_eq!(first.revision, 1);
        assert_eq!(store.reddit_subscriptions("guild-a").unwrap().len(), 1);

        let changed = RedditSubscriptionWrite {
            source_subreddit: "rust".into(),
            target_channel_id: "987654321098765432".into(),
            message_template: "Changed: {permalink}".into(),
            mention: "@here".into(),
            enabled: true,
            interval_seconds: 600,
            created_by: "user-b".into(),
        };
        let second = store
            .publish_reddit_feature_setting(
                "guild-a",
                "social.reddit",
                true,
                r#"{"sourceSubreddit":"rust"}"#,
                Some(1),
                "user-b",
                &[],
                Some(&changed),
            )
            .unwrap();
        assert_eq!(second.revision, 2);

        let restored = store
            .publish_reddit_feature_setting(
                "guild-a",
                "social.reddit",
                true,
                r#"{"sourceSubreddit":"discordapp"}"#,
                Some(2),
                "user-c",
                &[],
                Some(&write),
            )
            .unwrap();
        assert_eq!(restored.revision, 3);
        let subscription = store.reddit_subscriptions("guild-a").unwrap();
        assert_eq!(subscription.len(), 1);
        assert_eq!(subscription[0].source_subreddit, "discordapp");
        assert_eq!(subscription[0].target_channel_id, "123456789012345678");
        assert!(subscription[0].enabled);

        let disabled = store
            .publish_reddit_feature_setting(
                "guild-a",
                "social.reddit",
                false,
                "{}",
                Some(3),
                "user-d",
                &[],
                Some(&RedditSubscriptionWrite {
                    enabled: false,
                    ..write
                }),
            )
            .unwrap();
        assert_eq!(disabled.revision, 4);
        assert!(!store.reddit_subscriptions("guild-a").unwrap()[0].enabled);
    }

    #[test]
    fn remaining_provider_rollbacks_restore_settings_and_subscriptions_atomically() {
        let store = Store::open(":memory:").unwrap();

        macro_rules! round_trip {
            (
                $guild:literal,
                $key:literal,
                $publish:ident,
                $list:ident,
                $initial:expr,
                $changed:expr,
                $initial_json:literal,
                $changed_json:literal
            ) => {{
                let initial = $initial;
                let changed = $changed;
                assert_eq!(
                    store
                        .$publish(
                            $guild,
                            $key,
                            true,
                            $initial_json,
                            None,
                            "owner-a",
                            &[],
                            Some(&initial),
                        )
                        .unwrap()
                        .revision,
                    1
                );
                assert_eq!(
                    store
                        .$publish(
                            $guild,
                            $key,
                            true,
                            $changed_json,
                            Some(1),
                            "owner-b",
                            &[],
                            Some(&changed),
                        )
                        .unwrap()
                        .revision,
                    2
                );
                assert_eq!(
                    store
                        .$publish(
                            $guild,
                            $key,
                            true,
                            $initial_json,
                            Some(2),
                            "owner-c",
                            &[],
                            Some(&initial),
                        )
                        .unwrap()
                        .revision,
                    3
                );
                let settings = store.feature_settings($key).unwrap();
                assert_eq!(settings.len(), 1);
                assert_eq!(settings[0].guild_id, $guild);
                assert_eq!(settings[0].config_json, $initial_json);
                let rows = store.$list($guild).unwrap();
                assert_eq!(rows.len(), 1);
                rows
            }};
        }

        let rss = round_trip!(
            "guild-rss-rollback",
            "social.rss",
            publish_rss_feature_setting,
            rss_subscriptions,
            RssSubscriptionWrite {
                feed_url: "https://example.com/old.xml".into(),
                target_channel_id: "123456789012345678".into(),
                message_template: "Old {url}".into(),
                mention: "".into(),
                enabled: true,
                interval_seconds: 300,
                created_by: "owner-a".into(),
            },
            RssSubscriptionWrite {
                feed_url: "https://example.com/new.xml".into(),
                target_channel_id: "987654321098765432".into(),
                message_template: "New {url}".into(),
                mention: "@here".into(),
                enabled: true,
                interval_seconds: 600,
                created_by: "owner-b".into(),
            },
            r#"{"feedUrl":"https://example.com/old.xml"}"#,
            r#"{"feedUrl":"https://example.com/new.xml"}"#
        );
        assert_eq!(rss[0].feed_url, "https://example.com/old.xml");
        assert_eq!(rss[0].target_channel_id, "123456789012345678");
        assert_eq!(rss[0].message_template, "Old {url}");
        assert_eq!(rss[0].mention, "");
        assert_eq!(rss[0].interval_seconds, 300);

        let bluesky = round_trip!(
            "guild-bluesky-rollback",
            "social.bluesky",
            publish_bluesky_feature_setting,
            bluesky_subscriptions,
            BlueskySubscriptionWrite {
                source_handle: "old.example".into(),
                target_channel_id: "123456789012345678".into(),
                message_template: "Old {url}".into(),
                mention: "".into(),
                enabled: true,
                interval_seconds: 300,
                created_by: "owner-a".into(),
            },
            BlueskySubscriptionWrite {
                source_handle: "new.example".into(),
                target_channel_id: "987654321098765432".into(),
                message_template: "New {url}".into(),
                mention: "@here".into(),
                enabled: true,
                interval_seconds: 600,
                created_by: "owner-b".into(),
            },
            r#"{"sourceHandle":"old.example"}"#,
            r#"{"sourceHandle":"new.example"}"#
        );
        assert_eq!(bluesky[0].source_handle, "old.example");
        assert_eq!(bluesky[0].target_channel_id, "123456789012345678");
        assert_eq!(bluesky[0].message_template, "Old {url}");

        let x = round_trip!(
            "guild-x-rollback",
            "social.x",
            publish_x_feature_setting,
            x_subscriptions,
            XSubscriptionWrite {
                source_handle: "old_handle".into(),
                target_channel_id: "123456789012345678".into(),
                message_template: "Old {url}".into(),
                mention: "".into(),
                enabled: true,
                interval_seconds: 900,
                created_by: "owner-a".into(),
            },
            XSubscriptionWrite {
                source_handle: "new_handle".into(),
                target_channel_id: "987654321098765432".into(),
                message_template: "New {url}".into(),
                mention: "@here".into(),
                enabled: true,
                interval_seconds: 1_200,
                created_by: "owner-b".into(),
            },
            r#"{"sourceHandle":"old_handle"}"#,
            r#"{"sourceHandle":"new_handle"}"#
        );
        assert_eq!(x[0].source_handle, "old_handle");
        assert_eq!(x[0].target_channel_id, "123456789012345678");
        assert_eq!(x[0].message_template, "Old {url}");

        let tiktok = round_trip!(
            "guild-tiktok-rollback",
            "social.tiktok",
            publish_tiktok_feature_setting,
            tiktok_subscriptions,
            TikTokSubscriptionWrite {
                source_label: "old_creator".into(),
                target_channel_id: "123456789012345678".into(),
                message_template: "Old {url}".into(),
                mention: "".into(),
                enabled: true,
                interval_seconds: 900,
                created_by: "owner-a".into(),
            },
            TikTokSubscriptionWrite {
                source_label: "new_creator".into(),
                target_channel_id: "987654321098765432".into(),
                message_template: "New {url}".into(),
                mention: "@here".into(),
                enabled: true,
                interval_seconds: 1_200,
                created_by: "owner-b".into(),
            },
            r#"{"sourceLabel":"old_creator"}"#,
            r#"{"sourceLabel":"new_creator"}"#
        );
        assert_eq!(tiktok[0].source_label, "old_creator");
        assert_eq!(tiktok[0].target_channel_id, "123456789012345678");
        assert_eq!(tiktok[0].message_template, "Old {url}");

        let instagram = round_trip!(
            "guild-instagram-rollback",
            "social.instagram",
            publish_instagram_feature_setting,
            instagram_subscriptions,
            InstagramSubscriptionWrite {
                source_label: "old_account".into(),
                target_channel_id: "123456789012345678".into(),
                message_template: "Old {url}".into(),
                mention: "".into(),
                enabled: true,
                interval_seconds: 900,
                created_by: "owner-a".into(),
            },
            InstagramSubscriptionWrite {
                source_label: "new_account".into(),
                target_channel_id: "987654321098765432".into(),
                message_template: "New {url}".into(),
                mention: "@here".into(),
                enabled: true,
                interval_seconds: 1_200,
                created_by: "owner-b".into(),
            },
            r#"{"sourceLabel":"old_account"}"#,
            r#"{"sourceLabel":"new_account"}"#
        );
        assert_eq!(instagram[0].source_label, "old_account");
        assert_eq!(instagram[0].target_channel_id, "123456789012345678");
        assert_eq!(instagram[0].message_template, "Old {url}");

        let kick = round_trip!(
            "guild-kick-rollback",
            "social.kick",
            publish_kick_feature_setting,
            kick_subscriptions,
            KickSubscriptionWrite {
                source_handle: "old_channel".into(),
                target_channel_id: "123456789012345678".into(),
                message_template: "Old {url}".into(),
                mention: "".into(),
                enabled: true,
                interval_seconds: 300,
                created_by: "owner-a".into(),
            },
            KickSubscriptionWrite {
                source_handle: "new_channel".into(),
                target_channel_id: "987654321098765432".into(),
                message_template: "New {url}".into(),
                mention: "@here".into(),
                enabled: true,
                interval_seconds: 600,
                created_by: "owner-b".into(),
            },
            r#"{"sourceHandle":"old_channel"}"#,
            r#"{"sourceHandle":"new_channel"}"#
        );
        assert_eq!(kick[0].source_handle, "old_channel");
        assert_eq!(kick[0].target_channel_id, "123456789012345678");
        assert_eq!(kick[0].message_template, "Old {url}");

        let twitch = round_trip!(
            "guild-twitch-rollback",
            "social.twitch",
            publish_twitch_feature_setting,
            twitch_subscriptions,
            TwitchSubscriptionWrite {
                source_login: "old_streamer".into(),
                source_user_id: "111111111".into(),
                target_channel_id: "123456789012345678".into(),
                message_template: "Old {url}".into(),
                mention: "".into(),
                enabled: true,
                created_by: "owner-a".into(),
            },
            TwitchSubscriptionWrite {
                source_login: "new_streamer".into(),
                source_user_id: "222222222".into(),
                target_channel_id: "987654321098765432".into(),
                message_template: "New {url}".into(),
                mention: "@here".into(),
                enabled: true,
                created_by: "owner-b".into(),
            },
            r#"{"sourceLogin":"old_streamer"}"#,
            r#"{"sourceLogin":"new_streamer"}"#
        );
        assert_eq!(twitch[0].source_login, "old_streamer");
        assert_eq!(twitch[0].source_user_id, "111111111");
        assert_eq!(twitch[0].target_channel_id, "123456789012345678");
        assert_eq!(twitch[0].message_template, "Old {url}");
    }

    #[test]
    fn bluesky_subscription_round_trip_and_poll_state_are_guild_scoped() {
        let store = Store::open(":memory:").unwrap();
        let first = store
            .create_bluesky_subscription(
                "guild-a",
                "example.com",
                "123456789012345678",
                "New post: {text} {url}",
                "",
                true,
                300,
                "owner-a",
            )
            .unwrap();
        assert_eq!(first.source_handle, "example.com");
        assert!(store.bluesky_subscriptions("guild-b").unwrap().is_empty());
        assert_eq!(store.bluesky_subscriptions("guild-a").unwrap().len(), 1);

        store
            .update_bluesky_poll(
                first.id,
                Some("at://did:plc:test/app.bsky.feed.post/abc"),
                0,
                0,
                None,
            )
            .unwrap();
        let due = store.due_bluesky_subscriptions(1, 10).unwrap();
        assert_eq!(
            due[0].last_post_uri.as_deref(),
            Some("at://did:plc:test/app.bsky.feed.post/abc")
        );

        let updated = store
            .update_bluesky_subscription(
                "guild-a",
                first.id,
                "updates.example.com",
                "987654321098765432",
                "{handle}: {text}",
                "@here",
                false,
                900,
            )
            .unwrap()
            .unwrap();
        assert_eq!(updated.source_handle, "updates.example.com");
        assert!(!updated.enabled);
        assert!(
            !store
                .delete_bluesky_subscription("guild-b", first.id)
                .unwrap()
        );
        assert!(
            store
                .delete_bluesky_subscription("guild-a", first.id)
                .unwrap()
        );
        assert!(store.bluesky_subscriptions("guild-a").unwrap().is_empty());
    }

    #[test]
    fn reddit_subscription_round_trip_and_poll_state_are_guild_scoped() {
        let store = Store::open(":memory:").unwrap();
        let first = store
            .create_reddit_subscription(
                "guild-a",
                "vozen",
                "123456789012345678",
                "New post: {title} {permalink}",
                "",
                true,
                900,
                "owner-a",
            )
            .unwrap();
        assert_eq!(first.source_subreddit, "vozen");
        assert!(store.reddit_subscriptions("guild-b").unwrap().is_empty());
        assert_eq!(store.reddit_subscriptions("guild-a").unwrap().len(), 1);

        store
            .update_reddit_poll(first.id, Some("t3_post-1"), 0, 0, None)
            .unwrap();
        let due = store.due_reddit_subscriptions(1, 10).unwrap();
        assert_eq!(due[0].last_post_id.as_deref(), Some("t3_post-1"));

        let updated = store
            .update_reddit_subscription(
                "guild-a",
                first.id,
                "announcements",
                "987654321098765432",
                "{subreddit}: {title}",
                "@here",
                false,
                1800,
            )
            .unwrap()
            .unwrap();
        assert_eq!(updated.source_subreddit, "announcements");
        assert!(!updated.enabled);
        assert!(
            !store
                .delete_reddit_subscription("guild-b", first.id)
                .unwrap()
        );
        assert!(
            store
                .delete_reddit_subscription("guild-a", first.id)
                .unwrap()
        );
        assert!(store.reddit_subscriptions("guild-a").unwrap().is_empty());
    }

    #[test]
    fn x_subscription_round_trip_and_poll_state_are_guild_scoped() {
        let store = Store::open(":memory:").unwrap();
        let first = store
            .create_x_subscription(
                "guild-a",
                "vozen",
                "123456789012345678",
                "New post: {text} {url}",
                "",
                true,
                900,
                "owner-a",
            )
            .unwrap();
        assert_eq!(first.source_handle, "vozen");
        assert!(store.x_subscriptions("guild-b").unwrap().is_empty());
        assert_eq!(store.x_subscriptions("guild-a").unwrap().len(), 1);
        store
            .update_x_poll(first.id, Some("tweet-1"), 0, 0, None)
            .unwrap();
        let due = store.due_x_subscriptions(1, 10).unwrap();
        assert_eq!(due[0].last_post_id.as_deref(), Some("tweet-1"));
        let updated = store
            .update_x_subscription(
                "guild-a",
                first.id,
                "rexy40407",
                "987654321098765432",
                "{handle}: {text}",
                "@here",
                false,
                1800,
            )
            .unwrap()
            .unwrap();
        assert_eq!(updated.source_handle, "rexy40407");
        assert!(!updated.enabled);
        assert!(!store.delete_x_subscription("guild-b", first.id).unwrap());
        assert!(store.delete_x_subscription("guild-a", first.id).unwrap());
        assert!(store.x_subscriptions("guild-a").unwrap().is_empty());
    }

    #[test]
    fn tiktok_subscription_round_trip_and_poll_state_are_guild_scoped() {
        let store = Store::open(":memory:").unwrap();
        let first = store
            .create_tiktok_subscription(
                "guild-a",
                "Vozen Creator",
                "123456789012345678",
                "{label}: {title} {url}",
                "",
                true,
                900,
                "owner-a",
            )
            .unwrap();
        assert_eq!(first.source_label, "Vozen Creator");
        assert!(store.tiktok_subscriptions("guild-b").unwrap().is_empty());
        assert_eq!(store.tiktok_subscriptions("guild-a").unwrap().len(), 1);
        store
            .update_tiktok_poll(first.id, Some("video-1"), 0, 0, None)
            .unwrap();
        let due = store.due_tiktok_subscriptions(1, 10).unwrap();
        assert_eq!(due[0].last_video_id.as_deref(), Some("video-1"));
        let updated = store
            .update_tiktok_subscription(
                "guild-a",
                first.id,
                "Another Creator",
                "987654321098765432",
                "{title}",
                "@here",
                false,
                1_800,
            )
            .unwrap()
            .unwrap();
        assert_eq!(updated.source_label, "Another Creator");
        assert!(!updated.enabled);
        assert!(
            !store
                .delete_tiktok_subscription("guild-b", first.id)
                .unwrap()
        );
        assert!(
            store
                .delete_tiktok_subscription("guild-a", first.id)
                .unwrap()
        );
    }

    #[test]
    fn settings_prefix_counts_are_guild_scoped() {
        let store = Store::open(":memory:").unwrap();
        store.set_setting("g1", "support.panel.1", "{}").unwrap();
        store.set_setting("g1", "support.panel.2", "{}").unwrap();
        store
            .set_setting("g1", "community.role_panel.1", "{}")
            .unwrap();
        store.set_setting("g2", "support.panel.3", "{}").unwrap();
        assert_eq!(
            store.count_settings_prefix("g1", "support.panel.").unwrap(),
            2
        );
        assert_eq!(
            store
                .count_settings_prefix("g1", "community.role_panel.")
                .unwrap(),
            1
        );
        assert_eq!(
            store.count_settings_prefix("g2", "support.panel.").unwrap(),
            1
        );
    }

    #[test]
    fn suggestions_keep_the_published_channel_and_remove_failed_drafts() {
        let store = Store::open(":memory:").unwrap();
        let unpublished = store
            .create_suggestion_in_channel("guild", "author", "First", Some("123"))
            .unwrap();
        assert_eq!(
            store
                .suggestion(unpublished)
                .unwrap()
                .unwrap()
                .channel_id
                .as_deref(),
            Some("123")
        );
        assert!(
            store
                .delete_unpublished_suggestion("guild", unpublished)
                .unwrap()
        );
        assert!(store.suggestion(unpublished).unwrap().is_none());
        assert!(
            store
                .latest_suggestion_created_at("guild", "author")
                .unwrap()
                .is_none()
        );

        let published = store
            .create_suggestion_in_channel("guild", "author", "Second", Some("456"))
            .unwrap();
        store.set_suggestion_message(published, "789").unwrap();
        assert!(
            !store
                .delete_unpublished_suggestion("guild", published)
                .unwrap()
        );
        assert_eq!(
            store
                .suggestion(published)
                .unwrap()
                .unwrap()
                .channel_id
                .as_deref(),
            Some("456")
        );
    }

    #[test]
    fn migration_keeps_legacy_suggestions_and_adds_channel_id() {
        let path = std::env::temp_dir().join(format!(
            "vozen-helper-legacy-suggestions-{}.db",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let legacy = Connection::open(&path).unwrap();
        legacy.execute_batch(
            "CREATE TABLE suggestions (id INTEGER PRIMARY KEY AUTOINCREMENT, guild_id TEXT NOT NULL, author_id TEXT NOT NULL, content TEXT NOT NULL, message_id TEXT, status TEXT NOT NULL DEFAULT 'pending', created_at INTEGER NOT NULL); INSERT INTO suggestions(guild_id,author_id,content,created_at) VALUES('g','u','Legacy suggestion',1);",
        ).unwrap();
        drop(legacy);

        let store = Store::open(path.to_str().unwrap()).unwrap();
        assert_eq!(store.suggestion(1).unwrap().unwrap().channel_id, None);
        let id = store
            .create_suggestion_in_channel("g", "u", "New suggestion", Some("123"))
            .unwrap();
        assert_eq!(
            store.suggestion(id).unwrap().unwrap().channel_id.as_deref(),
            Some("123")
        );
        drop(store);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn events_and_suggestions_round_trip() {
        let store = Store::open(":memory:").unwrap();
        assert!(store.register_event("g", "event-1", "u").unwrap());
        assert!(!store.register_event("g", "event-1", "u").unwrap());
        assert!(store.check_in_event("g", "event-1", "u").unwrap());
        assert_eq!(
            store
                .event_registration("g", "event-1", "u")
                .unwrap()
                .unwrap()
                .status,
            "checked_in"
        );
        assert_eq!(
            store
                .register_event_with_capacity("g", "limited", "first", Some(1))
                .unwrap()
                .as_deref(),
            Some("registered")
        );
        assert_eq!(
            store
                .register_event_with_capacity("g", "limited", "second", Some(1))
                .unwrap()
                .as_deref(),
            Some("waitlisted")
        );
        assert_eq!(
            store
                .remove_event_registration("g", "limited", "first")
                .unwrap(),
            (true, Some("second".to_string()))
        );
        assert_eq!(
            store
                .event_registration("g", "limited", "second")
                .unwrap()
                .unwrap()
                .status,
            "registered"
        );
        let suggestion = store
            .create_suggestion("g", "u", "Add a weekly event")
            .unwrap();
        assert!(
            store
                .latest_suggestion_created_at("g", "u")
                .unwrap()
                .is_some()
        );
        assert!(
            store
                .latest_suggestion_created_at("g", "missing")
                .unwrap()
                .is_none()
        );
        store.vote_suggestion(suggestion, "voter", 1).unwrap();
        assert_eq!(store.suggestion_votes(suggestion).unwrap(), (1, 0));
        assert!(
            store
                .set_suggestion_status("g", suggestion, "approved")
                .unwrap()
        );

        let giveaway = store
            .create_giveaway("g", "10", "Prize", 2, i64::MAX, None, "u")
            .unwrap();
        assert!(store.add_giveaway_entry(giveaway, "winner").unwrap());
        assert!(!store.add_giveaway_entry(giveaway, "winner").unwrap());
        assert_eq!(store.giveaway_entries(giveaway).unwrap(), vec!["winner"]);
        assert!(store.end_giveaway(giveaway).unwrap());

        let poll = store
            .create_poll("g", "10", "Choose", &["A".into(), "B".into()], i64::MAX)
            .unwrap();
        store.vote_poll(poll, "voter", 1).unwrap();
        assert_eq!(store.poll_counts(poll, 2).unwrap(), vec![0, 1]);
        assert!(store.close_poll(poll).unwrap());

        let workflow = store
            .create_workflow("g", "welcome", "message", "hello", "reply", "Hi {user}")
            .unwrap();
        assert_eq!(
            store.active_workflows("g", "message").unwrap()[0].id,
            workflow
        );
        assert!(
            store
                .record_workflow_run(workflow, "g", "message-1")
                .unwrap()
        );
        assert!(
            !store
                .record_workflow_run(workflow, "g", "message-1")
                .unwrap()
        );
        assert!(store.delete_workflow("g", workflow).unwrap());
        store
            .save_quarantine("g", "u", &["10".into(), "20".into()], "raid")
            .unwrap();
        assert_eq!(
            store.get_quarantine("g", "u").unwrap().unwrap().role_ids,
            vec!["10", "20"]
        );
        assert!(store.clear_quarantine("g", "u").unwrap());
    }

    #[test]
    fn guild_export_and_purge_are_scoped() {
        let store = Store::open(":memory:").unwrap();
        store.set_setting("g1", "welcome.channel", "10").unwrap();
        store
            .set_setting("g1", "automation.webhook_secret", "must-not-export")
            .unwrap();
        store.upsert_tag("g1", "rules", "be kind", "u1").unwrap();
        store.set_birthday("g1", "u1", 8, 3).unwrap();
        store.claim_daily("g1", "u1", 25).unwrap();
        store
            .create_workflow("g1", "hello", "message", "hi", "reply", "Hello")
            .unwrap();
        store
            .record_case("g1", "warn", "u1", "mod", "reason", None)
            .unwrap();
        store
            .record_case("g2", "warn", "u2", "mod", "reason", None)
            .unwrap();

        let export = store.export_guild("g1").unwrap();
        assert_eq!(export["guildId"], "g1");
        assert_eq!(export["settings"][0]["key"], "welcome.channel");
        assert!(!export.to_string().contains("must-not-export"));
        assert_eq!(export["tags"][0]["name"], "rules");
        assert_eq!(export["workflows"][0]["name"], "hello");
        assert_eq!(export["birthdays"][0]["userId"], "u1");

        store.purge_guild("g1").unwrap();
        assert!(store.recent_cases("g1", 10).unwrap().is_empty());
        assert!(
            store
                .get_setting("g1", "welcome.channel")
                .unwrap()
                .is_none()
        );
        assert!(store.get_tag("g1", "rules").unwrap().is_none());
        assert_eq!(store.recent_cases("g2", 10).unwrap().len(), 1);
    }

    #[test]
    fn xp_events_are_idempotent_and_guild_scoped() {
        let store = Store::open(":memory:").unwrap();
        assert_eq!(
            store
                .add_xp_event("g1", "u1", "message:42", "message", 25, 100)
                .unwrap(),
            Some(25)
        );
        assert_eq!(
            store
                .add_xp_event("g1", "u1", "message:42", "message", 25, 101)
                .unwrap(),
            None
        );
        assert_eq!(store.level_for("g1", "u1").unwrap(), 25);
        assert_eq!(
            store
                .add_xp_event("g2", "u1", "message:42", "message", 10, 102)
                .unwrap(),
            Some(10)
        );
        assert_eq!(store.level_for("g2", "u1").unwrap(), 10);
        assert!(
            store
                .add_xp_event("g1", "u1", "", "message", 1, 103)
                .is_err()
        );
    }

    #[test]
    fn guild_purge_removes_feature_history_feeds_and_draw_results() {
        let store = Store::open(":memory:").unwrap();
        {
            let conn = store.conn.lock().unwrap();
            conn.execute_batch("INSERT INTO helper_sessions(id,user_id,guild_id,issued_at,expires_at,last_seen_at) VALUES('session','member','g1','2026-09-30T00:00:00Z','2026-10-01T00:00:00Z','2026-09-30T00:00:00Z'); INSERT INTO helper_entitlements(subject_id,payload,fetched_at) VALUES('member','{}','2026-09-30T00:00:00Z');").unwrap();
        }
        let mut draws = Vec::new();
        for guild in ["g1", "g2"] {
            store
                .publish_feature_setting(guild, "community.levels", true, "{}", None, "mod", &[])
                .unwrap();
            store
                .create_rss_subscription(
                    guild,
                    "https://example.com/feed.xml",
                    "10",
                    "{title}",
                    "",
                    true,
                    300,
                    "mod",
                )
                .unwrap();
            store.register_event(guild, "event", "member").unwrap();
            let draw = store
                .create_giveaway(
                    guild,
                    "10",
                    "prize",
                    1,
                    Utc::now().timestamp_millis() + 60_000,
                    None,
                    "host",
                )
                .unwrap();
            store.add_giveaway_entry(draw, "member").unwrap();
            store.prepare_giveaway_result(guild, draw).unwrap().unwrap();
            draws.push(draw);
        }
        store.purge_guild("g1").unwrap();
        store.purge_guild("g1").unwrap();
        assert!(
            !store
                .feature_settings("community.levels")
                .unwrap()
                .iter()
                .any(|record| record.guild_id == "g1")
        );
        assert!(
            store
                .feature_revisions("g1", "community.levels", 10)
                .unwrap()
                .is_empty()
        );
        assert!(store.rss_subscriptions("g1").unwrap().is_empty());
        assert!(
            store
                .feature_settings("community.levels")
                .unwrap()
                .iter()
                .any(|record| record.guild_id == "g2")
        );
        assert_eq!(store.rss_subscriptions("g2").unwrap().len(), 1);
        let conn = store.conn.lock().unwrap();
        for table in ["helper_sessions", "helper_entitlements"] {
            assert_eq!(
                conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| row
                    .get::<_, i64>(0))
                    .unwrap(),
                1
            );
        }
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM giveaway_results WHERE giveaway_id=?1",
                [draws[0]],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM giveaway_results WHERE giveaway_id=?1",
                [draws[1]],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
            1
        );
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM event_registrations WHERE guild_id='g1'",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM event_registrations WHERE guild_id='g2'",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
            1
        );
    }

    #[test]
    fn retention_removes_expired_draw_results_without_orphans() {
        let store = Store::open(":memory:").unwrap();
        let now = Utc::now().timestamp_millis();
        let mut draws = Vec::new();
        for end_at in [now - Duration::days(91).num_milliseconds(), now] {
            let draw = store
                .create_giveaway("g", "10", "prize", 1, end_at, None, "host")
                .unwrap();
            store.prepare_giveaway_result("g", draw).unwrap().unwrap();
            draws.push(draw);
        }
        store.conn.lock().unwrap().execute("INSERT INTO giveaway_results(giveaway_id,winners_json) VALUES(-1,'[\"legacy-orphan\"]')", []).unwrap();
        let summary = store.prune_retention(now).unwrap();
        assert_eq!(summary.deleted["giveaway_results"], 2);
        let conn = store.conn.lock().unwrap();
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM giveaway_results", [], |row| row
                .get::<_, i64>(0))
                .unwrap(),
            1
        );
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM giveaway_results WHERE giveaway_id=?1",
                [draws[0]],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM giveaway_results WHERE giveaway_id=?1",
                [draws[1]],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
            1
        );
    }

    #[test]
    fn voice_sessions_are_idempotent_and_bounded() {
        let store = Store::open(":memory:").unwrap();
        store
            .start_voice_session("g1", "u1", "voice-a", 1_000)
            .unwrap();
        // A repeated gateway event replaces the snapshot rather than creating
        // a second session for the same member.
        store
            .start_voice_session("g1", "u1", "voice-a", 1_030)
            .unwrap();
        assert_eq!(
            store
                .active_voice_session("g1", "u1")
                .unwrap()
                .unwrap()
                .channel_id,
            "voice-a"
        );
        assert_eq!(
            store.finish_voice_session("g1", "u1", 4_690).unwrap(),
            Some(61)
        );
        // Finishing twice cannot award the same session twice.
        assert_eq!(store.finish_voice_session("g1", "u1", 9_000).unwrap(), None);

        store
            .start_voice_session("g1", "u1", "voice-b", 2_000)
            .unwrap();
        // Negative clock movement produces no negative XP.
        assert_eq!(
            store.finish_voice_session("g1", "u1", 1_900).unwrap(),
            Some(0)
        );
        store.start_voice_session("g1", "u1", "voice-c", 0).unwrap();
        assert_eq!(
            store.finish_voice_session("g1", "u1", 99_999_999).unwrap(),
            Some(1_440)
        );
    }

    #[test]
    fn guild_config_import_is_validated_and_scoped() {
        let store = Store::open(":memory:").unwrap();
        store
            .set_setting("source", "welcome.channel", "10")
            .unwrap();
        store
            .upsert_tag("source", "rules", "be kind", "u1")
            .unwrap();
        store.set_birthday("source", "u1", 8, 3).unwrap();
        store
            .create_workflow("source", "hello", "message", "hi", "reply", "Hello")
            .unwrap();
        let export = store.export_guild("source").unwrap();

        let imported = store.import_guild_config("target", &export).unwrap();
        assert_eq!(imported.settings, 0);
        assert_eq!(imported.skipped_settings[0].key, "welcome.channel");
        assert_eq!(imported.tags, 1);
        assert_eq!(imported.workflows, 1);
        assert_eq!(imported.birthdays, 1);
        assert_eq!(
            store.get_setting("target", "welcome.channel").unwrap(),
            None
        );
        assert_eq!(
            store.get_tag("target", "rules").unwrap().unwrap().content,
            "be kind"
        );
        assert_eq!(
            store.active_workflows("target", "message").unwrap().len(),
            1
        );
        assert!(
            store
                .get_setting("source", "welcome.channel")
                .unwrap()
                .is_some()
        );

        assert_eq!(
            store.export_guild("target").unwrap()["birthdays"][0]["userId"],
            "u1"
        );

        let mut secret = export;
        secret["settings"] = serde_json::json!([{
            "key": "webhook_secret",
            "value": "must-reject"
        }]);
        assert!(store.import_guild_config("target", &secret).is_err());
    }

    #[test]
    fn guild_config_import_preserves_unicode_reaction_workflows() {
        let store = Store::open(":memory:").unwrap();
        store
            .create_workflow("source", "thank-you", "message", "thanks", "react", "✅")
            .unwrap();
        let export = store.export_guild("source").unwrap();

        store.import_guild_config("target", &export).unwrap();

        let workflow = store
            .active_workflows("target", "message")
            .unwrap()
            .into_iter()
            .next()
            .expect("imported reaction workflow");
        assert_eq!(workflow.action, "react");
        assert_eq!(workflow.payload, "✅");
    }

    #[test]
    fn prepared_import_rolls_back_all_features_arrays_and_projections_on_revision_conflict() {
        let store = Store::open(":memory:").unwrap();
        store
            .publish_feature_setting("target", "utility.help", true, "{}", None, "old", &[])
            .unwrap();
        let document = serde_json::json!({"version":1,"settings":[],"tags":[{"name":"rules","content":"hello","authorId":"forged"}],"workflows":[]});
        let prepared = Store::prepare_guild_config_import("target", &document).unwrap();
        let feature = |key: &str| ConfigImportFeature {
            key: key.into(),
            enabled: false,
            config_json: "{}".into(),
            expected_revision: 0,
            projections: vec![(format!("feature.{key}"), "false".into())],
            subscription: ImportSubscription::None,
        };
        assert!(
            store
                .apply_guild_config_import(
                    "target",
                    &prepared,
                    "actor",
                    &[feature("utility.reminders"), feature("utility.help")],
                    &[],
                    &ConfigImportLimits::default()
                )
                .is_err()
        );
        assert!(
            store
                .get_feature_setting("target", "utility.reminders")
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .get_setting("target", "feature.utility.reminders")
                .unwrap()
                .is_none()
        );
        assert!(store.get_tag("target", "rules").unwrap().is_none());
        assert_eq!(
            store
                .get_feature_setting("target", "utility.help")
                .unwrap()
                .unwrap()
                .revision,
            1
        );
    }

    #[test]
    fn prepared_import_rechecks_merged_workflow_quota_inside_transaction() {
        let store = Store::open(":memory:").unwrap();
        let document = serde_json::json!({"version":1,"settings":[],"tags":[],"workflows":[{"name":"new","trigger":"message","action":"reply","payload":"hi"}]});
        let prepared = Store::prepare_guild_config_import("target", &document).unwrap();
        let limits = ConfigImportLimits {
            workflows: 1,
            ..Default::default()
        };
        store
            .validate_guild_config_import_limits("target", &prepared, &limits)
            .unwrap();
        store
            .create_workflow("target", "concurrent", "message", "", "reply", "hi")
            .unwrap();
        assert!(
            store
                .apply_guild_config_import("target", &prepared, "actor", &[], &[], &limits)
                .is_err()
        );
        assert_eq!(store.workflows("target", 100).unwrap().len(), 1);
    }

    #[test]
    fn user_privacy_export_and_purge_keep_moderation_records() {
        let store = Store::open(":memory:").unwrap();
        store.set_afk("g1", "u1", "away").unwrap();
        store.add_xp("g1", "u1", 42).unwrap();
        store
            .start_voice_session("g1", "u1", "voice", Utc::now().timestamp())
            .unwrap();
        store.upsert_tag("g1", "mine", "hello", "u1").unwrap();
        store.set_birthday("g1", "u1", 8, 3).unwrap();
        store.claim_daily("g1", "u1", 25).unwrap();
        let suggestion = store.create_suggestion("g1", "u1", "feature").unwrap();
        store.vote_suggestion(suggestion, "u2", 1).unwrap();
        store
            .schedule_typed("g1", "reminder", "u1", 10, "{}")
            .unwrap();
        store.register_event("g1", "event-1", "u1").unwrap();
        store
            .record_case("g1", "warn", "u1", "mod", "kept", None)
            .unwrap();

        let export = store.export_user("g1", "u1").unwrap();
        assert_eq!(export["userId"], "u1");
        assert_eq!(export["moderationCases"].as_array().unwrap().len(), 1);
        assert!(export["voluntary"].as_array().unwrap().len() >= 3);
        assert!(
            export["voluntary"]
                .as_array()
                .unwrap()
                .iter()
                .any(|entry| entry["kind"] == "economy_transaction")
        );
        assert_eq!(export["suggestions"].as_array().unwrap().len(), 1);

        let result = store.purge_user("g1", "u1").unwrap();
        assert!(
            result["deleted"]
                .as_object()
                .unwrap()
                .contains_key("levels")
        );
        assert!(store.recent_cases("g1", 10).unwrap().len() == 1);
        assert!(store.get_tag("g1", "mine").unwrap().is_none());
        assert!(store.due_birthdays(8, 3, 2026, 10).unwrap().is_empty());
        assert!(store.get_afk("g1", "u1").unwrap().is_none());
        assert!(store.active_voice_session("g1", "u1").unwrap().is_none());
        assert!(
            store.export_user("g1", "u1").unwrap()["voluntary"]
                .as_array()
                .unwrap()
                .iter()
                .all(|entry| entry["kind"] != "economy_transaction")
        );
        assert_eq!(store.suggestion_votes(suggestion).unwrap(), (0, 0));
    }

    #[test]
    fn retention_sweep_removes_expired_records_and_keeps_recent_cases() {
        let store = Store::open(":memory:").unwrap();
        let now = Utc::now().timestamp_millis();
        let old_31d = now - Duration::days(31).num_milliseconds();
        let old_91d = now - Duration::days(91).num_milliseconds();
        let old_3y = now - Duration::days(1_095).num_milliseconds();
        store
            .record_case("g", "warn", "recent", "mod", "keep", None)
            .unwrap();
        {
            let conn = store.conn.lock().unwrap();
            conn.execute(
                "INSERT INTO audit_events(correlation_id,guild_id,actor_id,action,reason,before_json,after_json,outcome,created_at) VALUES('old-correlation','g','mod','old','old','{}','{}','recorded',?1)",
                [old_31d],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO activity_log(guild_id,type,user_id,actor_id,detail,created_at) VALUES('g','leave','u','mod','{}',?1)",
                [old_91d],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO cases(guild_id,type,target_id,moderator_id,reason,created_at) VALUES('g','old','u','mod','old',?1)",
                [old_3y],
            )
            .unwrap();
        }
        let summary = store.prune_retention(now).unwrap();
        assert_eq!(summary.deleted["audit_events"], 1);
        assert_eq!(summary.deleted["activity_log"], 1);
        assert_eq!(summary.deleted["cases"], 1);
        assert_eq!(store.recent_cases("g", 10).unwrap().len(), 1);
        assert_eq!(store.recent_audit_events("g", 10).unwrap().len(), 1);
    }

    #[test]
    fn youtube_subscriptions_round_trip_and_due_poll() {
        let store = Store::open(":memory:").unwrap();
        let record = store
            .create_youtube_subscription(
                "g",
                "UC123",
                "123456789012345",
                "{title} {url}",
                "",
                true,
                300,
                "u",
            )
            .unwrap();
        assert_eq!(store.youtube_subscriptions("g").unwrap().len(), 1);
        assert_eq!(
            store
                .due_youtube_subscriptions(Utc::now().timestamp_millis(), 10)
                .unwrap()
                .len(),
            1
        );
        store
            .update_youtube_poll(
                record.id,
                Some("video-1"),
                Utc::now().timestamp_millis() + 60_000,
                0,
                None,
            )
            .unwrap();
        let saved = store.youtube_subscriptions("g").unwrap().pop().unwrap();
        assert_eq!(saved.last_video_id.as_deref(), Some("video-1"));
        assert!(store.delete_youtube_subscription("g", record.id).unwrap());
        assert!(store.youtube_subscriptions("g").unwrap().is_empty());
    }

    #[test]
    fn rss_subscriptions_round_trip_and_due_poll() {
        let store = Store::open(":memory:").unwrap();
        let record = store
            .create_rss_subscription(
                "g",
                "https://example.com/feed.xml",
                "123456789012345",
                "{title} {url}",
                "",
                true,
                300,
                "u",
            )
            .unwrap();
        assert_eq!(store.rss_subscriptions("g").unwrap().len(), 1);
        assert_eq!(
            store
                .due_rss_subscriptions(Utc::now().timestamp_millis(), 10)
                .unwrap()
                .len(),
            1
        );
        store
            .update_rss_poll(
                record.id,
                Some("item-1"),
                Utc::now().timestamp_millis() + 60_000,
                0,
                None,
            )
            .unwrap();
        let saved = store.rss_subscriptions("g").unwrap().pop().unwrap();
        assert_eq!(saved.last_item_id.as_deref(), Some("item-1"));
        assert!(store.delete_rss_subscription("g", record.id).unwrap());
        assert!(store.rss_subscriptions("g").unwrap().is_empty());
    }

    #[test]
    fn twitch_subscriptions_stage_and_ack_are_idempotent() {
        let store = Store::open(":memory:").unwrap();
        let record = store
            .create_twitch_subscription(
                "g",
                "creator",
                "12345",
                "123456789012345",
                "{broadcaster} {url}",
                "",
                true,
                "u",
            )
            .unwrap();
        assert_eq!(
            store
                .stage_twitch_event("12345", "event-1", "stream-1", "2026-08-02T00:00:00Z")
                .unwrap(),
            1
        );
        assert_eq!(
            store
                .stage_twitch_event("12345", "event-1", "stream-1", "2026-08-02T00:00:00Z")
                .unwrap(),
            0
        );
        let due = store
            .due_twitch_subscriptions(Utc::now().timestamp_millis(), 10)
            .unwrap();
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].pending_event_id.as_deref(), Some("event-1"));
        assert!(
            store
                .ack_twitch_event(record.id, "event-1", i64::MAX, 0, None)
                .unwrap()
        );
        assert!(
            store
                .due_twitch_subscriptions(Utc::now().timestamp_millis(), 10)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn instagram_and_kick_subscriptions_round_trip_and_dedupe_provider_events() {
        let store = Store::open(":memory:").unwrap();
        let instagram = store
            .create_instagram_subscription(
                "g",
                "creator",
                "123456789012345",
                "{label} {url}",
                "",
                true,
                900,
                "u",
            )
            .unwrap();
        let kick = store
            .create_kick_subscription(
                "g",
                "streamer",
                "123456789012346",
                "{handle} {url}",
                "",
                true,
                300,
                "u",
            )
            .unwrap();
        assert_eq!(store.instagram_subscriptions("g").unwrap().len(), 1);
        assert_eq!(store.kick_subscriptions("g").unwrap().len(), 1);
        let now = Utc::now().timestamp_millis();
        assert_eq!(store.due_instagram_subscriptions(now, 10).unwrap().len(), 1);
        assert_eq!(store.due_kick_subscriptions(now, 10).unwrap().len(), 1);
        store
            .update_instagram_poll(instagram.id, Some("media-1"), now + 60_000, 0, None)
            .unwrap();
        store
            .update_kick_poll(kick.id, Some("stream-1"), now + 60_000, 0, None)
            .unwrap();
        assert_eq!(
            store.instagram_subscriptions("g").unwrap()[0]
                .last_media_id
                .as_deref(),
            Some("media-1")
        );
        assert_eq!(
            store.kick_subscriptions("g").unwrap()[0]
                .last_stream_id
                .as_deref(),
            Some("stream-1")
        );
        assert!(
            store
                .delete_instagram_subscription("g", instagram.id)
                .unwrap()
        );
        assert!(store.delete_kick_subscription("g", kick.id).unwrap());
        assert!(
            store
                .record_provider_event("stripe", "evt-1", "{}")
                .unwrap()
        );
        assert!(
            !store
                .record_provider_event("stripe", "evt-1", "{}")
                .unwrap()
        );
        assert!(
            store
                .record_provider_event("stripe", "evt-2", "{}")
                .unwrap()
        );
    }

    #[test]
    fn member_departure_deletes_only_voluntary_state() {
        let store = Store::open(":memory:").unwrap();
        store.set_afk("g", "u", "away").unwrap();
        store.add_xp("g", "u", 42).unwrap();
        store.upsert_tag("g", "mine", "hello", "u").unwrap();
        store.set_birthday("g", "u", 8, 3).unwrap();
        let suggestion = store.create_suggestion("g", "u", "remove me").unwrap();
        store.vote_suggestion(suggestion, "u", 1).unwrap();
        store.register_event("g", "event-1", "u").unwrap();
        store
            .record_case("g", "warn", "u", "mod", "kept", None)
            .unwrap();
        let deleted = store.delete_member_voluntary_data("g", "u").unwrap();
        assert_eq!(deleted["levels"], 1);
        assert_eq!(deleted["afk"], 1);
        assert_eq!(deleted["tags"], 1);
        assert_eq!(deleted["birthdays"], 1);
        assert_eq!(deleted["suggestions"], 1);
        assert_eq!(deleted["event_registrations"], 1);
        assert_eq!(store.level_for("g", "u").unwrap(), 0);
        assert!(store.get_afk("g", "u").unwrap().is_none());
        assert!(store.get_tag("g", "mine").unwrap().is_none());
        assert!(store.due_birthdays(8, 3, 2026, 10).unwrap().is_empty());
        assert_eq!(store.suggestion_votes(suggestion).unwrap(), (0, 0));
        assert_eq!(store.recent_cases("g", 10).unwrap().len(), 1);
    }

    #[test]
    fn birthdays_are_idempotent_per_year() {
        let store = Store::open(":memory:").unwrap();
        store.set_birthday("g", "u", 8, 3).unwrap();
        assert_eq!(store.due_birthdays(8, 3, 2026, 10).unwrap().len(), 1);
        assert_eq!(
            store
                .due_birthdays_for_guild("g", 8, 3, 2026, 10)
                .unwrap()
                .len(),
            1
        );
        assert!(
            store
                .due_birthdays_for_guild("other", 8, 3, 2026, 10)
                .unwrap()
                .is_empty()
        );
        assert!(store.mark_birthday_announced("g", "u", 2026).unwrap());
        assert!(store.due_birthdays(8, 3, 2026, 10).unwrap().is_empty());
        assert_eq!(store.due_birthdays(8, 3, 2027, 10).unwrap().len(), 1);
        assert!(store.remove_birthday("g", "u").unwrap());
        assert!(store.due_birthdays(8, 3, 2027, 10).unwrap().is_empty());
    }

    #[test]
    fn migration_preserves_legacy_birthdays_and_adds_only_missing_timestamps() {
        for (label, extra_columns, expected_created, expected_updated) in [
            ("node", "", 0, 0),
            (
                "created",
                ", created_at INTEGER NOT NULL DEFAULT 123",
                123,
                0,
            ),
            (
                "updated",
                ", updated_at INTEGER NOT NULL DEFAULT 456",
                0,
                456,
            ),
            (
                "current",
                ", created_at INTEGER NOT NULL DEFAULT 123, updated_at INTEGER NOT NULL DEFAULT 456",
                123,
                456,
            ),
        ] {
            let path = std::env::temp_dir().join(format!(
                "vozen-helper-birthday-timestamps-{}-{label}.db",
                std::process::id()
            ));
            assert!(!path.exists(), "isolated fixture must not overwrite a file");
            let legacy = Connection::open(&path).unwrap();
            legacy.execute_batch(&format!(
                "CREATE TABLE birthdays (guild_id TEXT NOT NULL, user_id TEXT NOT NULL, day INTEGER NOT NULL, month INTEGER NOT NULL, last_announced_year INTEGER{extra_columns}, PRIMARY KEY(guild_id,user_id));
                 INSERT INTO birthdays(guild_id,user_id,day,month,last_announced_year) VALUES('guild-a','announced',18,10,2026),('guild-a','pending',29,2,NULL),('guild-b','other',18,10,2025);"
            )).unwrap();
            drop(legacy);
            let store = Store::open(&path).unwrap();
            for _ in 0..2 {
                store.migrate().unwrap();
                let conn = store.conn.lock().unwrap();
                let mut statement = conn.prepare("SELECT guild_id,user_id,day,month,last_announced_year,created_at,updated_at FROM birthdays ORDER BY guild_id,user_id").unwrap();
                let rows = statement
                    .query_map([], |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, u32>(2)?,
                            row.get::<_, u32>(3)?,
                            row.get::<_, Option<i32>>(4)?,
                            row.get::<_, i64>(5)?,
                            row.get::<_, i64>(6)?,
                        ))
                    })
                    .unwrap()
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .unwrap();
                assert_eq!(
                    rows,
                    vec![
                        (
                            "guild-a".into(),
                            "announced".into(),
                            18,
                            10,
                            Some(2026),
                            expected_created,
                            expected_updated
                        ),
                        (
                            "guild-a".into(),
                            "pending".into(),
                            29,
                            2,
                            None,
                            expected_created,
                            expected_updated
                        ),
                        (
                            "guild-b".into(),
                            "other".into(),
                            18,
                            10,
                            Some(2025),
                            expected_created,
                            expected_updated
                        ),
                    ],
                    "{label}: preserve members, dates, timestamps and announcement state"
                );
            }
            assert!(
                store
                    .due_birthdays_for_guild("guild-a", 10, 18, 2026, 10)
                    .unwrap()
                    .is_empty()
            );
            assert_eq!(
                store
                    .due_birthdays_for_guild("guild-b", 10, 18, 2026, 10)
                    .unwrap()
                    .len(),
                1
            );
            assert_eq!(
                store
                    .due_birthdays_for_guild("guild-a", 2, 29, 2026, 10)
                    .unwrap()
                    .len(),
                1
            );
            store
                .set_birthday("new-guild", "new-member", 10, 18)
                .unwrap();
            assert_eq!(
                store
                    .due_birthdays_for_guild("new-guild", 10, 18, 2026, 10)
                    .unwrap()
                    .len(),
                1
            );
            drop(store);
            let reopened = Store::open(&path).unwrap();
            assert!(
                reopened
                    .due_birthdays_for_guild("guild-a", 10, 18, 2026, 10)
                    .unwrap()
                    .is_empty()
            );
            assert_eq!(
                reopened
                    .due_birthdays_for_guild("new-guild", 10, 18, 2026, 10)
                    .unwrap()
                    .len(),
                1
            );
            drop(reopened);
            std::fs::remove_file(path).unwrap();
        }
    }

    #[test]
    fn migration_adds_birthday_announcement_column_to_legacy_database() {
        let path = std::env::temp_dir().join(format!(
            "vozen-helper-legacy-birthdays-{}.db",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let legacy = Connection::open(&path).unwrap();
        legacy
            .execute_batch(
                "CREATE TABLE birthdays (guild_id TEXT NOT NULL, user_id TEXT NOT NULL, month INTEGER NOT NULL, day INTEGER NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, PRIMARY KEY(guild_id,user_id));",
            )
            .unwrap();
        drop(legacy);

        let store = Store::open(&path).unwrap();
        store.set_birthday("g", "u", 8, 3).unwrap();
        assert_eq!(store.due_birthdays(8, 3, 2026, 10).unwrap().len(), 1);
        assert!(store.mark_birthday_announced("g", "u", 2026).unwrap());
        assert!(store.due_birthdays(8, 3, 2026, 10).unwrap().is_empty());
        drop(store);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn economy_daily_is_atomic_and_rate_limited() {
        let store = Store::open(":memory:").unwrap();
        assert_eq!(store.economy_account("g", "u").unwrap().balance, 0);
        let first = store.claim_daily("g", "u", 250).unwrap().unwrap();
        assert_eq!(first.balance, 250);
        assert!(store.claim_daily("g", "u", 250).unwrap().is_none());
        assert_eq!(store.economy_account("g", "u").unwrap().balance, 250);
        let deleted = store.delete_member_voluntary_data("g", "u").unwrap();
        assert_eq!(deleted["economy_ledger"], 1);
        assert_eq!(store.economy_account("g", "u").unwrap().balance, 0);
    }

    #[test]
    fn economy_work_uses_a_separate_idempotent_cooldown_and_leaderboard() {
        let store = Store::open(":memory:").unwrap();
        let first = store
            .claim_economy_reward("g", "u", "work", 75, 60_000)
            .unwrap()
            .unwrap();
        assert_eq!(first.balance, 75);
        assert!(
            store
                .claim_economy_reward("g", "u", "work", 75, 60_000)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            store.economy_top("g", 10).unwrap(),
            vec![("u".to_string(), 75)]
        );
        let deleted = store.delete_member_voluntary_data("g", "u").unwrap();
        assert_eq!(deleted["economy_cooldowns"], 1);
    }

    #[test]
    fn invite_snapshots_return_deltas_and_attribute_joins() {
        let store = Store::open(":memory:").unwrap();
        assert_eq!(
            store
                .observe_invite("g", "abc", 10, Some("inviter"))
                .unwrap(),
            None
        );
        assert_eq!(
            store
                .observe_invite("g", "abc", 10, Some("inviter"))
                .unwrap(),
            Some(10)
        );
        assert_eq!(
            store
                .observe_invite("g", "abc", 11, Some("inviter"))
                .unwrap(),
            Some(10)
        );
        store
            .record_invite_attribution("g", "member", "abc", Some("inviter"))
            .unwrap();
        assert_eq!(
            store.invite_attribution("g", "member").unwrap(),
            Some(("abc".to_string(), Some("inviter".to_string())))
        );
    }

    #[test]
    fn temporary_channels_are_idempotent_and_removable() {
        let store = Store::open(":memory:").unwrap();
        store.register_temp_channel("g", "c", "u").unwrap();
        store.register_temp_channel("g", "c", "u").unwrap();
        assert_eq!(store.temp_channel("c").unwrap().unwrap().owner_id, "u");
        assert_eq!(store.active_temp_channels("g").unwrap(), 1);
        assert_eq!(store.temp_channels("g").unwrap().len(), 1);
        assert!(store.temp_channels("other").unwrap().is_empty());
        assert!(store.remove_temp_channel("c").unwrap());
        assert!(store.temp_channel("c").unwrap().is_none());
        assert_eq!(store.active_temp_channels("g").unwrap(), 0);
        assert!(!store.remove_temp_channel("c").unwrap());
    }

    #[test]
    fn anti_raid_latch_preserves_the_original_gate_until_its_last_expiry() {
        let store = Store::open(":memory:").unwrap();
        store
            .set_setting("guild", "security.join_gate.enabled", "false")
            .unwrap();

        store.arm_anti_raid_latch("guild", 100).unwrap();
        // A second burst extends containment, but must not overwrite the
        // original manual join-gate state with the temporary `true` value.
        store.arm_anti_raid_latch("guild", 120).unwrap();

        assert_eq!(
            store
                .get_setting("guild", "security.anti_raid.previous_gate_enabled")
                .unwrap()
                .as_deref(),
            Some("false")
        );
        assert!(!store.release_expired_anti_raid_latch("guild", 119).unwrap());
        assert!(store.release_expired_anti_raid_latch("guild", 120).unwrap());
        assert_eq!(
            store
                .get_setting("guild", "security.join_gate.enabled")
                .unwrap()
                .as_deref(),
            Some("false")
        );
        assert_eq!(
            store
                .get_setting("guild", "security.anti_raid.latch_active")
                .unwrap()
                .as_deref(),
            Some("false")
        );
    }

    #[test]
    fn expired_or_malformed_anti_raid_latches_are_released_for_recovery() {
        let store = Store::open(":memory:").unwrap();
        store
            .set_setting("expired", "security.join_gate.enabled", "true")
            .unwrap();
        store
            .set_setting(
                "expired",
                "security.anti_raid.previous_gate_enabled",
                "false",
            )
            .unwrap();
        store
            .set_setting("expired", "security.anti_raid.latch_active", "true")
            .unwrap();
        store
            .set_setting(
                "expired",
                "security.anti_raid.gate_until",
                "not-a-timestamp",
            )
            .unwrap();

        assert_eq!(
            store.active_anti_raid_latch_guilds(10).unwrap(),
            vec!["expired".to_string()]
        );
        assert!(store.release_expired_anti_raid_latch("expired", 1).unwrap());
        assert_eq!(
            store
                .get_setting("expired", "security.join_gate.enabled")
                .unwrap()
                .as_deref(),
            Some("false")
        );
        assert!(store.active_anti_raid_latch_guilds(10).unwrap().is_empty());
    }

    #[test]
    fn path_bytes_counts_nested_runtime_files_and_resolves_symlinks() {
        let root =
            std::env::temp_dir().join(format!("vozen-helper-footprint-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("nested")).unwrap();
        std::fs::write(root.join("binary"), vec![0u8; 7]).unwrap();
        std::fs::write(root.join("nested/data"), vec![0u8; 9]).unwrap();
        assert_eq!(path_bytes(&root), 16);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn tiktok_creator_grants_are_isolated_per_guild_and_replace_rotated_tokens() {
        let store = Store::open(":memory:").unwrap();
        store
            .save_tiktok_grant(
                "guild-a",
                "creator-a",
                "Creator A",
                "sealed-access-a",
                "sealed-refresh-a",
                "user.info.basic,video.list",
                1_000,
                2_000,
                100,
            )
            .unwrap();
        store
            .save_tiktok_grant(
                "guild-b",
                "creator-b",
                "Creator B",
                "sealed-access-b",
                "sealed-refresh-b",
                "user.info.basic,video.list",
                1_100,
                2_100,
                101,
            )
            .unwrap();

        let grant_a = store.tiktok_grant("guild-a").unwrap().unwrap();
        assert_eq!(grant_a.open_id, "creator-a");
        assert_eq!(grant_a.access_token_sealed, "sealed-access-a");
        assert_eq!(grant_a.display_name, "Creator A");
        assert_eq!(
            store.tiktok_grant("guild-b").unwrap().unwrap().open_id,
            "creator-b"
        );

        store
            .save_tiktok_grant(
                "guild-a",
                "creator-a",
                "Creator A",
                "sealed-access-rotated",
                "sealed-refresh-rotated",
                "user.info.basic,video.list",
                3_000,
                4_000,
                200,
            )
            .unwrap();
        let rotated = store.tiktok_grant("guild-a").unwrap().unwrap();
        assert_eq!(rotated.access_token_sealed, "sealed-access-rotated");
        assert_eq!(rotated.updated_at, 200);
        assert!(store.delete_tiktok_grant("guild-a").unwrap());
        assert!(store.tiktok_grant("guild-a").unwrap().is_none());
        assert!(store.tiktok_grant("guild-b").unwrap().is_some());
    }
}
