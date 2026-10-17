//! Discord gateway boundary. Handlers stay thin and delegate to core/modules.

use anyhow::Result;
use chrono::{DateTime, Datelike, Duration as ChronoDuration, FixedOffset, TimeZone, Utc};
use helper_contracts::{AntiSpamObservation, AntiSpamPolicy, Plan, is_valid_workflow_reaction};
use helper_core::{
    AchievementPolicy, AntiRaidPolicy, Config, JoinGateObservation, JoinGatePolicy,
    LeaderboardEntry, ModerationObservation, ModerationPolicy, ReminderObservation, ReminderPolicy,
    RolePanelObservation, StarboardObservation, WorkflowObservation, WorkflowPolicy,
    anti_spam_policy_from_json, evaluate_achievements, evaluate_anti_raid, evaluate_anti_spam,
    evaluate_audit, evaluate_birthday, evaluate_custom_command, evaluate_economy, evaluate_embed,
    evaluate_emojis, evaluate_event, evaluate_giveaway, evaluate_help, evaluate_invite_tracker,
    evaluate_join_gate, evaluate_leaderboard, evaluate_levels, evaluate_moderation,
    evaluate_nickname, evaluate_poll, evaluate_privacy, evaluate_reminder, evaluate_role_panel,
    evaluate_scam_with_roles, evaluate_search, evaluate_starboard, evaluate_stats_with_members,
    evaluate_suggestion, evaluate_temp_channel, evaluate_tickets, evaluate_welcome_channel,
    evaluate_workflow, feature_is_configurable, feature_maturity, leaderboard_policy_from_json,
    parse_utc_offset_minutes, quota_limit, render_bounded_template_message, render_member_message,
    render_welcome_message, scam_policy_from_json, starboard_policy_from_json,
};
use helper_modules::{
    BlueskyClient, BlueskyPost, CoinGeckoClient, CoinGeckoQuote, EntitlementClient,
    EthereumRpcClient, GasClient, GasQuote, InstagramClient, InstagramMedia, KickClient,
    KickStream, RssClient, TikTokClient, TikTokOAuthClient, TikTokVideo, TokenCipher,
    TwitchChannelSearchResult, TwitchClient, YouTubeClient, YouTubeSearchResult, env_flag_is_true,
    first_env_flag_is_true, format_rss_message, format_twitch_message, format_youtube_message,
    tiktok_runtime_allowed,
};
use helper_store::{
    BlueskySubscriptionRecord, InstagramSubscriptionRecord, KickSubscriptionRecord,
    RssSubscriptionRecord, Store, TikTokSubscriptionRecord, TopggSyncDetail,
    TwitchSubscriptionRecord, YouTubeSubscriptionRecord,
};
use rand::seq::SliceRandom;
use reqwest::Client as HttpClient;
use serenity::{
    all::{
        ButtonStyle, ChannelId, ChannelType, Client, Colour, Command, CommandDataOptionValue,
        CommandInteraction, Context, CreateActionRow, CreateAllowedMentions, CreateAttachment,
        CreateButton, CreateChannel, CreateCommand, CreateCommandOption, CreateEmbed,
        CreateEmbedFooter, CreateInteractionResponse, CreateInteractionResponseMessage,
        CreateMessage, EditChannel, EditInteractionResponse, EditMessage, EventHandler,
        GatewayIntents, Guild, Interaction, MessageId, MessageUpdateEvent, PermissionOverwrite,
        PermissionOverwriteType, Permissions, ReactionType, Ready, RoleId, UnavailableGuild,
    },
    async_trait,
};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use tracing::{info, warn};

pub mod giveaway_card;
mod giveaway_display;
mod rank_card;
pub mod starboard_card;
mod starboard_display;
pub mod suggestion_card;
mod suggestion_display;
mod topgg_metrics;

use crate::topgg_metrics::{
    ReqwestTopggMetricsHttp, TOPGG_POST_INTERVAL, TopggMetricsTrigger,
    post_topgg_stats_with_shards, validate_topgg_v1_token,
};

/// A small side-effect boundary used by policy tests. Production handlers
/// still use Serenity directly, while the fake makes permission failures and
/// emitted actions deterministic without connecting to Discord.
pub mod adapter {
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum Effect {
        Timeout {
            guild_id: String,
            member_id: String,
            seconds: u64,
            reason: String,
        },
        Log {
            channel_id: String,
            content: String,
        },
        Reply {
            channel_id: String,
            content: String,
        },
        CreateChannel {
            guild_id: String,
            channel_id: String,
            name: String,
            kind: String,
        },
        EditChannel {
            channel_id: String,
            name: String,
        },
        DeleteChannel {
            channel_id: String,
        },
        AssignRole {
            guild_id: String,
            member_id: String,
            role_id: String,
        },
        RemoveRole {
            guild_id: String,
            member_id: String,
            role_id: String,
        },
        ChangeNickname {
            guild_id: String,
            member_id: String,
            nickname: Option<String>,
        },
        PublishEvent {
            guild_id: String,
            event_id: String,
            name: String,
        },
    }

    pub trait DiscordAdapter {
        fn timeout_member(
            &mut self,
            guild_id: &str,
            member_id: &str,
            seconds: u64,
            reason: &str,
        ) -> Result<(), String>;
        fn log(&mut self, channel_id: &str, content: &str) -> Result<(), String>;
        fn reply(&mut self, channel_id: &str, content: &str) -> Result<(), String>;
        fn create_channel(
            &mut self,
            guild_id: &str,
            channel_id: &str,
            name: &str,
            kind: &str,
        ) -> Result<(), String>;
        fn edit_channel(&mut self, channel_id: &str, name: &str) -> Result<(), String>;
        fn delete_channel(&mut self, channel_id: &str) -> Result<(), String>;
        fn assign_role(
            &mut self,
            guild_id: &str,
            member_id: &str,
            role_id: &str,
        ) -> Result<(), String>;
        fn remove_role(
            &mut self,
            guild_id: &str,
            member_id: &str,
            role_id: &str,
        ) -> Result<(), String>;
        fn change_nickname(
            &mut self,
            guild_id: &str,
            member_id: &str,
            nickname: Option<&str>,
        ) -> Result<(), String>;
        fn publish_event(
            &mut self,
            guild_id: &str,
            event_id: &str,
            name: &str,
        ) -> Result<(), String>;
    }

    #[derive(Debug, Default, Clone)]
    pub struct FakeDiscordAdapter {
        effects: Vec<Effect>,
        fail_next: bool,
    }

    impl FakeDiscordAdapter {
        pub fn new() -> Self {
            Self::default()
        }

        pub fn effects(&self) -> &[Effect] {
            &self.effects
        }

        pub fn fail_next(&mut self) {
            self.fail_next = true;
        }

        fn check(&mut self) -> Result<(), String> {
            if self.fail_next {
                self.fail_next = false;
                Err("discord_permission_denied".into())
            } else {
                Ok(())
            }
        }
    }

    impl DiscordAdapter for FakeDiscordAdapter {
        fn timeout_member(
            &mut self,
            guild_id: &str,
            member_id: &str,
            seconds: u64,
            reason: &str,
        ) -> Result<(), String> {
            self.check()?;
            self.effects.push(Effect::Timeout {
                guild_id: guild_id.into(),
                member_id: member_id.into(),
                seconds,
                reason: reason.into(),
            });
            Ok(())
        }

        fn log(&mut self, channel_id: &str, content: &str) -> Result<(), String> {
            self.check()?;
            self.effects.push(Effect::Log {
                channel_id: channel_id.into(),
                content: content.into(),
            });
            Ok(())
        }

        fn reply(&mut self, channel_id: &str, content: &str) -> Result<(), String> {
            self.check()?;
            self.effects.push(Effect::Reply {
                channel_id: channel_id.into(),
                content: content.into(),
            });
            Ok(())
        }

        fn create_channel(
            &mut self,
            guild_id: &str,
            channel_id: &str,
            name: &str,
            kind: &str,
        ) -> Result<(), String> {
            self.check()?;
            self.effects.push(Effect::CreateChannel {
                guild_id: guild_id.into(),
                channel_id: channel_id.into(),
                name: name.into(),
                kind: kind.into(),
            });
            Ok(())
        }

        fn edit_channel(&mut self, channel_id: &str, name: &str) -> Result<(), String> {
            self.check()?;
            self.effects.push(Effect::EditChannel {
                channel_id: channel_id.into(),
                name: name.into(),
            });
            Ok(())
        }

        fn delete_channel(&mut self, channel_id: &str) -> Result<(), String> {
            self.check()?;
            self.effects.push(Effect::DeleteChannel {
                channel_id: channel_id.into(),
            });
            Ok(())
        }

        fn assign_role(
            &mut self,
            guild_id: &str,
            member_id: &str,
            role_id: &str,
        ) -> Result<(), String> {
            self.check()?;
            self.effects.push(Effect::AssignRole {
                guild_id: guild_id.into(),
                member_id: member_id.into(),
                role_id: role_id.into(),
            });
            Ok(())
        }

        fn remove_role(
            &mut self,
            guild_id: &str,
            member_id: &str,
            role_id: &str,
        ) -> Result<(), String> {
            self.check()?;
            self.effects.push(Effect::RemoveRole {
                guild_id: guild_id.into(),
                member_id: member_id.into(),
                role_id: role_id.into(),
            });
            Ok(())
        }

        fn change_nickname(
            &mut self,
            guild_id: &str,
            member_id: &str,
            nickname: Option<&str>,
        ) -> Result<(), String> {
            self.check()?;
            self.effects.push(Effect::ChangeNickname {
                guild_id: guild_id.into(),
                member_id: member_id.into(),
                nickname: nickname.map(str::to_owned),
            });
            Ok(())
        }

        fn publish_event(
            &mut self,
            guild_id: &str,
            event_id: &str,
            name: &str,
        ) -> Result<(), String> {
            self.check()?;
            self.effects.push(Effect::PublishEvent {
                guild_id: guild_id.into(),
                event_id: event_id.into(),
                name: name.into(),
            });
            Ok(())
        }
    }
}

type DuplicateMessageCache = Arc<Mutex<HashMap<String, VecDeque<(Instant, String)>>>>;

/// Exact process-local view of guild membership for Top.gg. IDs never leave
/// the process: persistence keeps only aggregate counts and delivery health.
#[derive(Clone, Default)]
struct TopggGuilds {
    ids: Arc<Mutex<HashSet<u64>>>,
    ready: Arc<AtomicBool>,
}

impl TopggGuilds {
    fn set_ready(&self, guilds: impl IntoIterator<Item = u64>) {
        let mut ids = self.ids.lock().expect("topgg guild set mutex poisoned");
        ids.clear();
        ids.extend(guilds);
        self.ready.store(true, Ordering::Release);
    }

    fn insert(&self, guild_id: u64) -> bool {
        self.ids
            .lock()
            .expect("topgg guild set mutex poisoned")
            .insert(guild_id)
    }

    fn remove(&self, guild_id: u64) -> bool {
        self.ids
            .lock()
            .expect("topgg guild set mutex poisoned")
            .remove(&guild_id)
    }

    fn count(&self) -> usize {
        self.ids
            .lock()
            .expect("topgg guild set mutex poisoned")
            .len()
    }

    fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }
}

#[derive(Clone)]
struct Handler {
    store: Store,
    spam: Arc<Mutex<HashMap<String, VecDeque<Instant>>>>,
    duplicate_messages: DuplicateMessageCache,
    spam_action_at: Arc<Mutex<HashMap<String, Instant>>>,
    joins: Arc<Mutex<HashMap<String, VecDeque<Instant>>>>,
    nuke_events: Arc<Mutex<HashMap<String, VecDeque<Instant>>>>,
    xp_awarded_at: Arc<Mutex<HashMap<String, Instant>>>,
    scheduler_started: Arc<AtomicBool>,
    topgg_trigger: Option<TopggMetricsTrigger>,
    topgg_guilds: Option<TopggGuilds>,
    entitlements: Option<EntitlementClient>,
    youtube: Option<YouTubeClient>,
    rss: Option<RssClient>,
    twitch: Option<TwitchClient>,
    bluesky: Option<BlueskyClient>,
    tiktok: Option<TikTokClient>,
    tiktok_oauth: Option<TikTokOAuthClient>,
    token_cipher: Option<TokenCipher>,
    instagram: Option<InstagramClient>,
    kick: Option<KickClient>,
    coingecko: Option<CoinGeckoClient>,
    gas: GasClient,
}

#[async_trait]
impl EventHandler for Handler {
    async fn guild_create(&self, _ctx: Context, guild: Guild, _is_new: Option<bool>) {
        // The store makes this idempotent, so startup GuildCreate replays do
        // not inflate acquisition. A first observation is intentionally a
        // join: it gives a newly enabled lifecycle table a valid baseline.
        let _ = self
            .store
            .record_growth_join(&guild.id.to_string(), Utc::now().timestamp_millis());
        if self
            .topgg_guilds
            .as_ref()
            .is_some_and(|guilds| guilds.insert(guild.id.get()))
            && let Some(trigger) = &self.topgg_trigger
        {
            trigger.request_sync();
        }
    }

    async fn guild_delete(
        &self,
        _ctx: Context,
        incomplete: UnavailableGuild,
        _full: Option<Guild>,
    ) {
        // Discord sends unavailable=true for a temporary outage. It is not a
        // bot removal and must never count as churn.
        if !incomplete.unavailable {
            let _ = self
                .store
                .record_growth_departure(&incomplete.id.to_string(), Utc::now().timestamp_millis());
            if self
                .topgg_guilds
                .as_ref()
                .is_some_and(|guilds| guilds.remove(incomplete.id.get()))
                && let Some(trigger) = &self.topgg_trigger
            {
                trigger.request_sync();
            }
        }
    }

    async fn ready(&self, ctx: Context, ready: Ready) {
        info!(user = %ready.user.name, "helper gateway ready");
        if let (Some(guilds), Some(trigger)) = (&self.topgg_guilds, &self.topgg_trigger) {
            guilds.set_ready(ready.guilds.iter().map(|guild| guild.id.get()));
            trigger.request_sync();
        }
        for guild in &ready.guilds {
            let guild_id = guild.id.to_string();
            if !feature_enabled(&self.store, &guild_id, "management.nickname", None) {
                continue;
            }
            let Some(nickname) = setting_string(&self.store, &guild_id, "identity.nickname") else {
                continue;
            };
            if let Err(error) = guild
                .id
                .edit_member(
                    &ctx.http,
                    ready.user.id,
                    serenity::all::EditMember::new().nickname(nickname.trim().to_owned()),
                )
                .await
            {
                warn!(%guild_id, %error, "failed to apply configured Helper nickname");
            }
        }
        if !self.scheduler_started.swap(true, Ordering::AcqRel) {
            let store = self.store.clone();
            let http = ctx.http.clone();
            tokio::spawn(async move {
                // Birthday policies can use different UTC offsets.  Check once
                // per minute instead of once per UTC day so a guild at UTC-14
                // or UTC+14 is still announced on its own local day.
                let mut last_birthday_minute: Option<i64> = None;
                loop {
                    if let Ok(actions) =
                        store.due_scheduled_actions(chrono::Utc::now().timestamp_millis(), 100)
                    {
                        for (id, guild_id, action_type, target_id, payload) in actions {
                            let _ = deliver_scheduled_action(
                                &http,
                                &store,
                                id,
                                &guild_id,
                                &action_type,
                                &target_id,
                                &payload,
                            )
                            .await;
                        }
                    }
                    let birthday_now = chrono::Utc::now();
                    let birthday_minute = birthday_now.timestamp().div_euclid(60);
                    if last_birthday_minute != Some(birthday_minute) {
                        let _ = deliver_birthday_announcements(&http, &store, birthday_now).await;
                        last_birthday_minute = Some(birthday_minute);
                    }
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            });
            let nickname_store = self.store.clone();
            let nickname_http = ctx.http.clone();
            tokio::spawn(async move {
                run_nickname_worker(nickname_http, nickname_store).await;
            });
            let anti_raid_store = self.store.clone();
            tokio::spawn(async move {
                run_anti_raid_expiry_worker(anti_raid_store).await;
            });
            let growth_lifecycle_store = self.store.clone();
            tokio::spawn(async move {
                run_growth_lifecycle_purge_worker(growth_lifecycle_store).await;
            });
            if let Some(youtube) = self.youtube.clone() {
                let store = self.store.clone();
                let http = ctx.http.clone();
                tokio::spawn(async move {
                    run_youtube_worker(http, store, youtube).await;
                });
            }
            if let Some(rss) = self.rss.clone() {
                let store = self.store.clone();
                let http = ctx.http.clone();
                tokio::spawn(async move {
                    run_rss_worker(http, store, rss).await;
                });
            }
            if self.twitch.is_some() {
                let store = self.store.clone();
                let http = ctx.http.clone();
                tokio::spawn(async move {
                    run_twitch_worker(http, store).await;
                });
            }
            if let Some(bluesky) = self.bluesky.clone() {
                let store = self.store.clone();
                let http = ctx.http.clone();
                tokio::spawn(async move {
                    run_bluesky_worker(http, store, bluesky).await;
                });
            }
            if self.tiktok.is_some() || self.tiktok_oauth.is_some() {
                let store = self.store.clone();
                let http = ctx.http.clone();
                let tiktok = self.tiktok.clone();
                let oauth = self.tiktok_oauth.clone();
                let cipher = self.token_cipher.clone();
                tokio::spawn(async move {
                    run_tiktok_worker(http, store, tiktok, oauth, cipher).await;
                });
            }
            if let Some(instagram) = self.instagram.clone() {
                let store = self.store.clone();
                let http = ctx.http.clone();
                tokio::spawn(async move {
                    run_instagram_worker(http, store, instagram).await;
                });
            }
            if let Some(kick) = self.kick.clone() {
                let store = self.store.clone();
                let http = ctx.http.clone();
                tokio::spawn(async move {
                    run_kick_worker(http, store, kick).await;
                });
            }
            if let Some(coingecko) = self.coingecko.clone() {
                let store = self.store.clone();
                let http = ctx.http.clone();
                tokio::spawn(async move {
                    run_crypto_stats_worker(http, store, coingecko).await;
                });
            }
            {
                let store = self.store.clone();
                let http = ctx.http.clone();
                tokio::spawn(async move {
                    run_stats_channel_worker(http, store).await;
                });
            }
            {
                let store = self.store.clone();
                let http = ctx.http.clone();
                let gas = self.gas.clone();
                tokio::spawn(async move {
                    run_gas_tracker_worker(http, store, gas).await;
                });
            }
        }

        // Prime invite usage snapshots once the gateway is ready.  The member
        // join event does not include the invite code, so attribution is only
        // safe when a baseline was captured before the join.  This is bounded
        // and uses Discord's official guild-invites endpoint; failures are
        // isolated to the affected guild and never stop the gateway.
        let invite_guilds = ready
            .guilds
            .iter()
            .filter_map(|guild| {
                let guild_id = guild.id;
                feature_enabled(
                    &self.store,
                    &guild_id.to_string(),
                    "management.invite_tracker",
                    None,
                )
                .then_some(guild_id)
            })
            .collect::<Vec<_>>();
        if !invite_guilds.is_empty() {
            let store = self.store.clone();
            let http = ctx.http.clone();
            tokio::spawn(async move {
                for guild_id in invite_guilds {
                    refresh_invite_snapshots(&http, &store, guild_id).await;
                    // Keep a reconnect with many guilds below Discord's
                    // burst limits without delaying the ready event.
                    tokio::time::sleep(Duration::from_millis(250)).await;
                }
            });
        }

        let commands = vec![
            CreateCommand::new("ping").description("Check Helper latency"),
            CreateCommand::new("language")
                .description("View or set the Helper language")
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::String,
                        "locale",
                        "Language for Helper messages",
                    )
                    .add_string_choice("English", "en")
                    .add_string_choice("Português", "pt")
                    .add_string_choice("Français", "fr")
                    .add_string_choice("Español", "es")
                    .add_string_choice("Deutsch", "de")
                    .add_string_choice("Türkçe", "tr")
                    .add_string_choice("العربية", "ar")
                    .add_string_choice("繁體中文", "zh")
                    .add_string_choice("Русский", "ru")
                    .add_string_choice("한국어", "ko")
                    .required(false),
                ),
            CreateCommand::new("help").description("Show Helper modules"),
            CreateCommand::new("setup")
                .description("Run the guided Helper setup for this server")
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::Boolean,
                        "security",
                        "Enable Security module",
                    )
                    .required(false),
                )
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::Boolean,
                        "support",
                        "Enable Support module",
                    )
                    .required(false),
                )
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::Boolean,
                        "events",
                        "Enable Events module",
                    )
                    .required(false),
                )
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::Boolean,
                        "community",
                        "Enable Community module",
                    )
                    .required(false),
                )
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::Boolean,
                        "automate",
                        "Enable Automate module",
                    )
                    .required(false),
                )
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::Boolean,
                        "insights",
                        "Enable Insights module",
                    )
                    .required(false),
                ),
            CreateCommand::new("modules").description("Show enabled Helper modules"),
            CreateCommand::new("status").description("Show Helper setup and health status"),
            CreateCommand::new("dashboard").description("Open the Helper dashboard"),
            CreateCommand::new("plan").description("Show the active Vozen plan"),
            CreateCommand::new("privacy")
                .description("Request your Helper data or erase voluntary data")
                .add_option(CreateCommandOption::new(
                    serenity::all::CommandOptionType::SubCommand,
                    "data",
                    "Explain how to export your data",
                ))
                .add_option(CreateCommandOption::new(
                    serenity::all::CommandOptionType::SubCommand,
                    "erase",
                    "Explain how to erase voluntary data",
                )),
            CreateCommand::new("permissions").description("Show the Helper Permission Passport"),
            CreateCommand::new("cases").description("List recent moderation cases"),
            CreateCommand::new("modlogs")
                .description("Show a member's moderation history")
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::User,
                        "user",
                        "Member",
                    )
                    .required(true),
                ),
            CreateCommand::new("warn")
                .description("Create a moderation warning")
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::User,
                        "user",
                        "Member to warn",
                    )
                    .required(true),
                )
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::String,
                        "reason",
                        "Reason",
                    )
                    .required(false),
                ),
            CreateCommand::new("violation")
                .description("Record a policy violation")
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::User,
                        "user",
                        "Member",
                    )
                    .required(true),
                )
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::String,
                        "rule",
                        "Rule or policy",
                    )
                    .required(true),
                )
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::String,
                        "details",
                        "Evidence or details",
                    )
                    .required(false),
                ),
            CreateCommand::new("note")
                .description("Add a moderation note")
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::User,
                        "user",
                        "Member",
                    )
                    .required(true),
                )
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::String,
                        "content",
                        "Note",
                    )
                    .required(true),
                ),
            CreateCommand::new("reason")
                .description("Update a case reason")
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::Integer,
                        "case",
                        "Case number",
                    )
                    .required(true),
                )
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::String,
                        "reason",
                        "New reason",
                    )
                    .required(true),
                ),
            CreateCommand::new("kick")
                .description("Kick a member")
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::User,
                        "user",
                        "Member to kick",
                    )
                    .required(true),
                )
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::String,
                        "reason",
                        "Reason",
                    )
                    .required(false),
                ),
            CreateCommand::new("ban")
                .description("Ban a member")
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::User,
                        "user",
                        "Member to ban",
                    )
                    .required(true),
                )
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::String,
                        "reason",
                        "Reason",
                    )
                    .required(false),
                ),
            CreateCommand::new("timeout")
                .description("Timeout a member")
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::User,
                        "user",
                        "Member to timeout",
                    )
                    .required(true),
                )
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::Integer,
                        "seconds",
                        "Duration in seconds (max 28 days)",
                    )
                    .required(false),
                )
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::String,
                        "reason",
                        "Reason",
                    )
                    .required(false),
                ),
            CreateCommand::new("tempban")
                .description("Temporarily ban a member; automatically unban after the duration")
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::User,
                        "user",
                        "Member",
                    )
                    .required(true),
                )
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::String,
                        "duration",
                        "Examples: 10m, 2h, 1d",
                    )
                    .required(true),
                )
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::String,
                        "reason",
                        "Reason",
                    )
                    .required(false),
                ),
            CreateCommand::new("softban")
                .description("Ban and immediately unban a member to clear recent messages")
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::User,
                        "user",
                        "Member",
                    )
                    .required(true),
                )
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::String,
                        "reason",
                        "Reason",
                    )
                    .required(false),
                ),
            CreateCommand::new("untimeout")
                .description("Remove a member timeout")
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::User,
                        "user",
                        "Member",
                    )
                    .required(true),
                ),
            CreateCommand::new("unban")
                .description("Unban a user")
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::String,
                        "user_id",
                        "User ID",
                    )
                    .required(true),
                ),
            CreateCommand::new("purge")
                .description("Delete recent messages")
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::Integer,
                        "count",
                        "Messages to delete (1-100)",
                    )
                    .required(true),
                ),
            CreateCommand::new("afk")
                .description("Set or clear your AFK status")
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::String,
                        "reason",
                        "Leave empty to clear AFK",
                    )
                    .required(false),
                ),
            CreateCommand::new("remind")
                .description("Create a durable reminder")
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::String,
                        "time",
                        "Examples: 10m, 2h, 1d or 09:30",
                    )
                    .required(true),
                )
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::String,
                        "text",
                        "Reminder text",
                    )
                    .required(true),
                )
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::String,
                        "repeat",
                        "Optional repeat interval",
                    )
                    .add_string_choice("Daily", "daily")
                    .add_string_choice("Weekly", "weekly")
                    .required(false),
                ),
            CreateCommand::new("tag")
                .description("Show a saved tag")
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::String,
                        "name",
                        "Tag name",
                    )
                    .required(true),
                ),
            CreateCommand::new("tags").description("List saved tags"),
            CreateCommand::new("birthday-set")
                .description("Save your birthday day and month")
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::Integer,
                        "month",
                        "Month (1-12)",
                    )
                    .required(true),
                )
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::Integer,
                        "day",
                        "Day (1-31)",
                    )
                    .required(true),
                ),
            CreateCommand::new("birthday-remove").description("Remove your saved birthday"),
            CreateCommand::new("tag-set")
                .description("Create or update a tag")
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::String,
                        "name",
                        "Tag name",
                    )
                    .required(true),
                )
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::String,
                        "content",
                        "Tag response",
                    )
                    .required(true),
                ),
            CreateCommand::new("tag-delete")
                .description("Delete a tag")
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::String,
                        "name",
                        "Tag name",
                    )
                    .required(true),
                ),
            CreateCommand::new("rank")
                .description("Show a member's XP rank")
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::User,
                        "user",
                        "Member",
                    )
                    .required(false),
                ),
            CreateCommand::new("leaderboard").description("Show the XP leaderboard"),
            CreateCommand::new("leaderboard-privacy")
                .description("Choose whether your XP appears on the leaderboard")
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::Boolean,
                        "opt_out",
                        "Hide your XP from this server's leaderboard",
                    )
                    .required(true),
                ),
            CreateCommand::new("achievements").description("Show your community achievements"),
            CreateCommand::new("serverstats").description("Show basic server statistics"),
            CreateCommand::new("crypto")
                .description("Show read-only CoinGecko prices")
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::String,
                        "coins",
                        "CoinGecko IDs separated by commas",
                    )
                    .required(true),
                )
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::String,
                        "currency",
                        "Currency such as usd or eur",
                    )
                    .required(false),
                ),
            CreateCommand::new("gas")
                .description("Show a read-only gas price from an approved RPC")
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::String,
                        "network",
                        "ethereum, polygon, arbitrum or base",
                    )
                    .add_string_choice("Ethereum", "ethereum")
                    .add_string_choice("Polygon", "polygon")
                    .add_string_choice("Arbitrum", "arbitrum")
                    .add_string_choice("Base", "base")
                    .required(false),
                ),
            CreateCommand::new("search")
                .description("Search an approved knowledge provider")
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::String,
                        "provider",
                        "youtube, twitch, wikipedia, anilist or bluesky",
                    )
                    .add_string_choice("YouTube", "youtube")
                    .add_string_choice("Twitch", "twitch")
                    .add_string_choice("Wikipedia", "wikipedia")
                    .add_string_choice("AniList", "anilist")
                    .add_string_choice("Bluesky", "bluesky")
                    .required(true),
                )
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::String,
                        "query",
                        "What to search for",
                    )
                    .required(true),
                ),
            CreateCommand::new("emojis").description("List this server's custom emojis"),
            CreateCommand::new("invites").description("Show current server invite usage"),
            CreateCommand::new("balance").description("Show your community balance"),
            CreateCommand::new("daily").description("Claim your daily community reward"),
            CreateCommand::new("work").description("Claim a cooldown-based community work reward"),
            CreateCommand::new("economy-top").description("Show the richest community members"),
            CreateCommand::new("temp-channel")
                .description("Create a temporary voice channel for yourself"),
            CreateCommand::new("embed")
                .description("Publish a safe embed in this channel (staff)")
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::String,
                        "title",
                        "Embed title",
                    )
                    .required(true),
                )
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::String,
                        "description",
                        "Embed description",
                    )
                    .required(true),
                )
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::String,
                        "color",
                        "Optional #RRGGBB accent colour",
                    )
                    .required(false),
                )
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::String,
                        "footer",
                        "Optional footer text",
                    )
                    .required(false),
                ),
            CreateCommand::new("starboard-set")
                .description("Configure the starboard channel (staff)")
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::Channel,
                        "channel",
                        "Starboard channel",
                    )
                    .required(true),
                ),
            CreateCommand::new("suggest")
                .description("Submit a community suggestion")
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::String,
                        "text",
                        "Suggestion text",
                    )
                    .required(true),
                ),
            CreateCommand::new("suggestion")
                .description("Review a community suggestion (staff)")
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::Integer,
                        "id",
                        "Suggestion ID",
                    )
                    .required(true),
                )
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::String,
                        "status",
                        "pending, approved, denied or considered",
                    )
                    .required(true),
                ),
            CreateCommand::new("giveaway-start")
                .description("Start a durable giveaway (staff)")
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::String,
                        "prize",
                        "Prize",
                    )
                    .required(true),
                )
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::String,
                        "duration",
                        "Examples: 10m, 2h, 1d",
                    )
                    .required(true),
                )
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::Integer,
                        "winners",
                        "Number of winners",
                    )
                    .required(false),
                )
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::Role,
                        "required_role",
                        "Optional required role",
                    )
                    .required(false),
                ),
            CreateCommand::new("gstart")
                .description("Legacy alias for giveaway-start")
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::String,
                        "prize",
                        "Prize",
                    )
                    .required(true),
                )
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::String,
                        "duration",
                        "Examples: 10m, 2h, 1d",
                    )
                    .required(true),
                )
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::Integer,
                        "winners",
                        "Number of winners",
                    )
                    .required(false),
                )
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::Role,
                        "required_role",
                        "Optional required role",
                    )
                    .required(false),
                ),
            CreateCommand::new("giveaway-end")
                .description("End a giveaway now (staff)")
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::Integer,
                        "id",
                        "Giveaway ID",
                    )
                    .required(true),
                ),
            CreateCommand::new("gend")
                .description("Legacy alias for giveaway-end")
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::Integer,
                        "id",
                        "Giveaway ID",
                    )
                    .required(true),
                ),
            CreateCommand::new("giveaway-list").description("List active giveaways"),
            CreateCommand::new("glist").description("Legacy alias for giveaway-list"),
            CreateCommand::new("greroll")
                .description("Reroll a finished giveaway")
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::Integer,
                        "id",
                        "Giveaway ID",
                    )
                    .required(true),
                ),
            CreateCommand::new("poll")
                .description("Create a multi-choice poll")
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::String,
                        "question",
                        "Question",
                    )
                    .required(true),
                )
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::String,
                        "option1",
                        "Option 1",
                    )
                    .required(true),
                )
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::String,
                        "option2",
                        "Option 2",
                    )
                    .required(true),
                )
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::String,
                        "option3",
                        "Option 3",
                    )
                    .required(false),
                )
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::String,
                        "option4",
                        "Option 4",
                    )
                    .required(false),
                )
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::String,
                        "option5",
                        "Option 5",
                    )
                    .required(false),
                )
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::String,
                        "duration",
                        "Examples: 10m, 2h, 1d",
                    )
                    .required(false),
                ),
            CreateCommand::new("workflow-create")
                .description("Create a bounded message automation (staff)")
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::String,
                        "name",
                        "Workflow name",
                    )
                    .required(true),
                )
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::String,
                        "reply",
                        "Reply text; use {user} and {message}",
                    )
                    .required(false),
                )
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::String,
                        "emoji",
                        "One Unicode emoji to add as a reaction",
                    )
                    .required(false),
                )
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::String,
                        "contains",
                        "Only run when message contains this text",
                    )
                    .required(false),
                ),
            CreateCommand::new("workflow-list").description("List message automations"),
            CreateCommand::new("workflow-dry-run")
                .description("Preview a workflow without executing it (staff)")
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::Integer,
                        "id",
                        "Workflow ID",
                    )
                    .required(true),
                )
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::String,
                        "message",
                        "Sample message",
                    )
                    .required(true),
                ),
            CreateCommand::new("workflow-toggle")
                .description("Enable or disable a workflow immediately (staff)")
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::Integer,
                        "id",
                        "Workflow ID",
                    )
                    .required(true),
                )
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::Boolean,
                        "enabled",
                        "Enable workflow",
                    )
                    .required(true),
                ),
            CreateCommand::new("workflow-delete")
                .description("Delete a message automation (staff)")
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::Integer,
                        "id",
                        "Workflow ID",
                    )
                    .required(true),
                ),
            CreateCommand::new("ticket-panel").description("Create a support ticket panel"),
            CreateCommand::new("ticket-config")
                .description("Configure ticket routing, transcripts and SLA (staff)")
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::Role,
                        "staff_role",
                        "Role that can see tickets",
                    )
                    .required(false),
                )
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::Channel,
                        "transcript_channel",
                        "Transcript channel",
                    )
                    .required(false),
                )
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::Integer,
                        "sla_minutes",
                        "SLA reminder in minutes",
                    )
                    .required(false),
                ),
            CreateCommand::new("ticket-update")
                .description("Update ticket category, priority or internal note")
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::String,
                        "priority",
                        "Ticket priority",
                    )
                    .add_string_choice("Baixa", "low")
                    .add_string_choice("Normal", "normal")
                    .add_string_choice("Alta", "high")
                    .add_string_choice("Urgente", "urgent")
                    .required(false),
                )
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::String,
                        "category",
                        "Ticket category",
                    )
                    .required(false),
                )
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::String,
                        "note",
                        "Internal note (empty clears it)",
                    )
                    .required(false),
                ),
            CreateCommand::new("ticket-rate")
                .description("Rate a closed support ticket")
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::Integer,
                        "score",
                        "Satisfaction score from 1 to 5",
                    )
                    .required(true),
                ),
            CreateCommand::new("rolepanel")
                .description("Create a self-role panel")
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::String,
                        "title",
                        "Panel title",
                    )
                    .required(true),
                )
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::Role,
                        "role1",
                        "Role 1",
                    )
                    .required(true),
                )
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::Role,
                        "role2",
                        "Role 2",
                    )
                    .required(false),
                )
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::Role,
                        "role3",
                        "Role 3",
                    )
                    .required(false),
                )
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::Role,
                        "role4",
                        "Role 4",
                    )
                    .required(false),
                )
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::Role,
                        "role5",
                        "Role 5",
                    )
                    .required(false),
                ),
            CreateCommand::new("slowmode")
                .description("Set channel slowmode")
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::Integer,
                        "seconds",
                        "Seconds from 0 to 21600",
                    )
                    .required(true),
                ),
            CreateCommand::new("userinfo")
                .description("Show basic user information")
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::User,
                        "user",
                        "User",
                    )
                    .required(true),
                ),
            CreateCommand::new("quarantine")
                .description("Remove a member's roles and quarantine them")
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::User,
                        "user",
                        "Member",
                    )
                    .required(true),
                )
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::String,
                        "reason",
                        "Reason",
                    )
                    .required(false),
                ),
            CreateCommand::new("unquarantine")
                .description("Restore a quarantined member's roles")
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::User,
                        "user",
                        "Member",
                    )
                    .required(true),
                ),
            CreateCommand::new("join-gate")
                .description("Configure the bounded new-member join gate")
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::Boolean,
                        "enabled",
                        "Enable or disable the gate",
                    )
                    .required(true),
                )
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::Role,
                        "role",
                        "Role applied to new members while they verify",
                    )
                    .required(false),
                )
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::Integer,
                        "min_age_days",
                        "Flag accounts younger than this many days (0-365)",
                    )
                    .required(false),
                ),
            CreateCommand::new("verify-panel")
                .description("Post the verification panel using the configured join gate"),
            CreateCommand::new("lockdown")
                .description("Lock text channels for @everyone")
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::String,
                        "reason",
                        "Reason",
                    )
                    .required(false),
                ),
            CreateCommand::new("unlock")
                .description("Remove the Helper lockdown from text channels"),
            CreateCommand::new("anti-raid")
                .description("Configure the bounded join-burst anti-raid response")
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::Boolean,
                        "enabled",
                        "Enable or disable the response",
                    )
                    .required(true),
                )
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::Integer,
                        "joins",
                        "Join count that arms the response (2-100)",
                    )
                    .required(false),
                )
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::Integer,
                        "window_seconds",
                        "Sliding window in seconds (3-60)",
                    )
                    .required(false),
                )
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::Integer,
                        "incident_minutes",
                        "Temporary containment duration in minutes (1-120)",
                    )
                    .required(false),
                ),
            CreateCommand::new("security-mode")
                .description("Enable or disable shadow mode for high-risk security responses")
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::Boolean,
                        "shadow",
                        "Record and alert without automatic containment",
                    )
                    .required(true),
                ),
            CreateCommand::new("anti-nuke")
                .description("Configure the audit-log destructive-action guard")
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::Boolean,
                        "enabled",
                        "Enable or disable the guard",
                    )
                    .required(true),
                )
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::Integer,
                        "actions",
                        "Destructive actions that arm the guard (2-25)",
                    )
                    .required(false),
                )
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::Integer,
                        "window_seconds",
                        "Sliding window in seconds (3-60)",
                    )
                    .required(false),
                ),
            CreateCommand::new("event-create")
                .description("Create a native Discord scheduled event")
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::String,
                        "name",
                        "Event name",
                    )
                    .required(true),
                )
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::String,
                        "start",
                        "RFC3339 start, for example 2026-07-24T20:00:00Z",
                    )
                    .required(true),
                )
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::String,
                        "location",
                        "External event location",
                    )
                    .required(true),
                )
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::String,
                        "end",
                        "RFC3339 end",
                    )
                    .required(false),
                )
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::String,
                        "description",
                        "Optional event description",
                    )
                    .required(false),
                )
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::Integer,
                        "capacity",
                        "Optional attendee limit (1-100000)",
                    )
                    .required(false),
                ),
            CreateCommand::new("event-list").description("List native Discord scheduled events"),
            CreateCommand::new("event-edit")
                .description("Edit a native Discord scheduled event")
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::Integer,
                        "event_id",
                        "Discord scheduled event ID",
                    )
                    .required(true),
                )
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::String,
                        "name",
                        "New event name",
                    )
                    .required(false),
                )
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::String,
                        "start",
                        "New RFC3339 start",
                    )
                    .required(false),
                )
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::String,
                        "end",
                        "New RFC3339 end",
                    )
                    .required(false),
                )
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::String,
                        "location",
                        "New external event location",
                    )
                    .required(false),
                )
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::String,
                        "description",
                        "New event description (empty clears it)",
                    )
                    .required(false),
                ),
            CreateCommand::new("event-register")
                .description("Register yourself for a native Discord scheduled event")
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::Integer,
                        "event_id",
                        "Discord scheduled event ID",
                    )
                    .required(true),
                ),
            CreateCommand::new("event-unregister")
                .description("Remove yourself from a scheduled event")
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::Integer,
                        "event_id",
                        "Discord scheduled event ID",
                    )
                    .required(true),
                ),
            CreateCommand::new("event-checkin")
                .description("Check yourself in to a registered scheduled event")
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::Integer,
                        "event_id",
                        "Discord scheduled event ID",
                    )
                    .required(true),
                ),
            CreateCommand::new("event-attendees")
                .description("List registrations for a scheduled event")
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::Integer,
                        "event_id",
                        "Discord scheduled event ID",
                    )
                    .required(true),
                ),
            CreateCommand::new("event-cancel")
                .description("Cancel a native Discord scheduled event")
                .add_option(
                    CreateCommandOption::new(
                        serenity::all::CommandOptionType::Integer,
                        "event_id",
                        "Discord scheduled event ID",
                    )
                    .required(true),
                ),
        ];
        match Command::set_global_commands(&ctx.http, commands).await {
            Ok(registered) => info!(count = registered.len(), "global commands registered"),
            Err(error) => tracing::error!(%error, "global command registration failed"),
        }
    }

    async fn voice_state_update(
        &self,
        ctx: Context,
        old: Option<serenity::all::VoiceState>,
        new: serenity::all::VoiceState,
    ) {
        let Some(guild_id) = new
            .guild_id
            .or_else(|| old.as_ref().and_then(|state| state.guild_id))
        else {
            return;
        };
        let old_channel_id = old.as_ref().and_then(|state| state.channel_id);
        let new_channel_id = new.channel_id;
        let guild_text = guild_id.to_string();
        let user_text = new.user_id.to_string();

        if feature_enabled(&self.store, &guild_text, "management.audit", None) {
            let detail = serde_json::json!({
                "oldChannelId": old_channel_id.map(|channel| channel.to_string()),
                "newChannelId": new_channel_id.map(|channel| channel.to_string()),
                "contentAvailable": false,
            })
            .to_string();
            let _ = self.store.record_activity(
                &guild_text,
                "voice_state",
                &user_text,
                None,
                None,
                &detail,
            );
            if let Some(raw_channel) =
                setting_string(&self.store, &guild_text, "management.audit.log_channel")
                    .filter(|value| !value.trim().is_empty())
                && let Ok(log_channel) = raw_channel.parse::<u64>()
            {
                let from = old_channel_id
                    .map(|channel| format!("<#{}>", channel))
                    .unwrap_or_else(|| "not connected".into());
                let to = new_channel_id
                    .map(|channel| format!("<#{}>", channel))
                    .unwrap_or_else(|| "not connected".into());
                let _ = ChannelId::new(log_channel)
                    .say(
                        &ctx.http,
                        format!(
                            "Audit: <@{}> voice state changed from {from} to {to}.",
                            user_text
                        ),
                    )
                    .await;
            }
        }

        // Voice XP is session based: joins start a durable snapshot, moves
        // close the old snapshot before starting the new one, and leaves close
        // it without relying on a background timer. The store operation is
        // idempotent so duplicate gateway deliveries cannot double-award XP.
        if old_channel_id != new_channel_id
            && feature_enabled(&self.store, &guild_text, "community.levels", None)
            && setting_bool(
                &self.store,
                &guild_text,
                "community.levels.voice_xp_enabled",
                false,
            )
        {
            let now = Utc::now().timestamp();
            let ignored_channels = setting_string(
                &self.store,
                &guild_text,
                "community.levels.ignored_channels",
            )
            .unwrap_or_default();
            let is_ignored = |channel_id: Option<serenity::all::ChannelId>| {
                channel_id.is_some_and(|channel_id| {
                    ignored_channels
                        .split(',')
                        .map(str::trim)
                        .any(|ignored| ignored == channel_id.to_string())
                })
            };
            let previous_session = self
                .store
                .active_voice_session(&guild_text, &user_text)
                .ok()
                .flatten();
            if old_channel_id.is_some()
                && let Ok(Some(minutes)) =
                    self.store
                        .finish_voice_session(&guild_text, &user_text, now)
            {
                let before = self.store.level_for(&guild_text, &user_text).unwrap_or(0);
                let event_key = previous_session
                    .as_ref()
                    .map(|session| {
                        format!(
                            "voice:{}:{}:{}",
                            session.user_id, session.channel_id, session.started_at
                        )
                    })
                    .unwrap_or_else(|| format!("voice:{}:{}", user_text, now));
                let voice_channel = previous_session
                    .as_ref()
                    .map(|session| session.channel_id.as_str())
                    .unwrap_or_default();
                let decision = evaluate_levels(
                    &levels_config_for_store(&self.store, &guild_text),
                    "voice",
                    voice_channel,
                    &event_key,
                    true,
                    minutes.max(0) as u64,
                    before,
                );
                if decision.allowed {
                    match self.store.add_xp_event(
                        &guild_text,
                        &user_text,
                        &event_key,
                        "voice",
                        decision.amount,
                        now.saturating_mul(1_000),
                    ) {
                        Ok(Some(after)) => {
                            self.announce_achievement_unlocks(
                                &ctx, guild_id, &user_text, after, None,
                            )
                            .await;
                            self.apply_level_rewards(&ctx, guild_id, &user_text, after / 100 + 1)
                                .await;
                            if after / 100 > before / 100 {
                                info!(
                                    %guild_id,
                                    user = %new.user_id,
                                    xp = decision.amount,
                                    before,
                                    after,
                                    "voice XP awarded with level-up"
                                );
                            }
                        }
                        Ok(None) => {}
                        Err(error) => {
                            warn!(%guild_id, user = %new.user_id, %error, "failed to award voice XP");
                        }
                    }
                }
            }
            if let Some(channel_id) = new_channel_id
                && !is_ignored(Some(channel_id))
                && let Err(error) = self.store.start_voice_session(
                    &guild_text,
                    &user_text,
                    &channel_id.to_string(),
                    now,
                )
            {
                warn!(%guild_id, user = %new.user_id, %error, "failed to start voice XP session");
            }
        }

        // Temporary channel ownership cleanup remains independent from XP. A
        // member can leave/move through a normal voice channel without there
        // being a temp-channel record.
        if let Some(old_channel_id) = old_channel_id {
            let channel_id = old_channel_id.to_string();
            if let Ok(Some(record)) = self.store.temp_channel(&channel_id)
                && user_text == record.owner_id
            {
                // Moving the owner must not delete the room.  Without the
                // optional Serenity cache we cannot prove that a moved room
                // is empty, so only clean up after a full voice disconnect;
                // the next disconnect event can retry an orphaned room.
                if should_cleanup_temp_channel(new_channel_id) {
                    if let Err(error) = old_channel_id.delete(&ctx.http).await {
                        warn!(%guild_id, %old_channel_id, %error, "failed to remove ownerless temporary voice channel");
                    } else if let Err(error) = self.store.remove_temp_channel(&channel_id) {
                        warn!(%guild_id, %old_channel_id, %error, "failed to remove temporary channel record");
                    }
                }
            }
        }
    }

    async fn interaction_create(&self, ctx: Context, interaction: Interaction) {
        match interaction {
            Interaction::Command(command) => {
                // Acknowledge before provider, entitlement, or Discord requests.
                let ephemeral = command_response_ephemeral(&self.store, &command);
                if let Err(error) = command
                    .create_response(
                        &ctx,
                        CreateInteractionResponse::Defer(
                            CreateInteractionResponseMessage::new().ephemeral(ephemeral),
                        ),
                    )
                    .await
                {
                    warn!(%error, "command acknowledgement failed");
                    return;
                }
                if let Err(error) = self.handle_command(&ctx, &command).await {
                    tracing::error!(%error, command = %command.data.name, "command failed");
                    let _ = command
                        .edit_response(
                            &ctx,
                            EditInteractionResponse::new()
                                .content("Something went wrong while running that command."),
                        )
                        .await;
                } else if let Some(guild_id) = command.guild_id {
                    let now = Utc::now().timestamp_millis();
                    if command.data.name == "setup"
                        && helper_setup_is_complete(&self.store, &guild_id.to_string())
                    {
                        let _ = self
                            .store
                            .record_growth_setup_completed(&guild_id.to_string(), now);
                    }
                    if helper_command_counts_as_value(&command.data.name) {
                        let _ = self
                            .store
                            .record_growth_activity(&guild_id.to_string(), now);
                    }
                }
            }
            Interaction::Component(component) => {
                if let Err(error) = component.defer_ephemeral(&ctx).await {
                    warn!(%error, "component acknowledgement failed");
                    return;
                }
                if let Err(error) = self.handle_component(&ctx, &component).await {
                    tracing::error!(%error, "component failed");
                    let _ = component
                        .edit_response(
                            &ctx,
                            EditInteractionResponse::new()
                                .content("Unable to complete this action."),
                        )
                        .await;
                } else if let Some(guild_id) = component.guild_id {
                    let _ = self.store.record_growth_activity(
                        &guild_id.to_string(),
                        Utc::now().timestamp_millis(),
                    );
                }
            }
            _ => {}
        }
    }

    async fn guild_member_addition(&self, ctx: Context, new_member: serenity::all::Member) {
        let guild_id = new_member.guild_id;
        let day = chrono::Utc::now().format("%Y-%m-%d").to_string();
        let _ = self.store.record_join(&guild_id.to_string(), &day);
        let guild_text = guild_id.to_string();
        if feature_enabled(&self.store, &guild_text, "management.audit", None) {
            let detail = serde_json::json!({
                "event": "member_join",
                "contentAvailable": false,
            })
            .to_string();
            let _ = self.store.record_activity(
                &guild_text,
                "member_join",
                &new_member.user.id.to_string(),
                Some(&new_member.user.name),
                None,
                &detail,
            );
            if let Some(raw_channel) =
                setting_string(&self.store, &guild_text, "management.audit.log_channel")
                    .filter(|value| !value.trim().is_empty())
                && let Ok(log_channel) = raw_channel.parse::<u64>()
            {
                let _ = ChannelId::new(log_channel)
                    .say(
                        &ctx.http,
                        format!("Audit: <@{}> joined the server.", new_member.user.id),
                    )
                    .await;
            }
        }
        // Discord's member-add event does not carry an invite code. When the
        // invite tracker is enabled, compare the current usage counters with
        // the bounded snapshot from the previous observation and attribute a
        // join only when exactly one invite advanced. A missing/ambiguous
        // delta is deliberately left unattributed rather than guessed.
        if feature_enabled(&self.store, &guild_text, "management.invite_tracker", None)
            && let Ok(invites) = guild_id.invites(&ctx.http).await
        {
            let mut candidate: Option<(String, Option<String>, i64)> = None;
            for invite in invites {
                let inviter_id = invite.inviter.as_ref().map(|user| user.id.to_string());
                let previous = self
                    .store
                    .observe_invite(
                        &guild_text,
                        &invite.code,
                        invite.uses.min(9_999_999) as i64,
                        inviter_id.as_deref(),
                    )
                    .ok()
                    .flatten();
                let Some(previous) = previous else {
                    continue;
                };
                let delta = invite.uses as i64 - previous;
                // A single observed use is attributable to this join. If a
                // reconnect missed multiple joins, the delta is ambiguous and
                // must not be guessed.
                if delta == 1 {
                    if candidate.is_some() {
                        candidate = None;
                        break;
                    }
                    candidate = Some((invite.code, inviter_id, delta));
                }
            }
            if let Some((code, inviter_id, delta)) = candidate {
                let _ = self.store.record_invite_attribution(
                    &guild_text,
                    &new_member.user.id.to_string(),
                    &code,
                    inviter_id.as_deref(),
                );
                let _ = self.store.record_activity(
                    &guild_text,
                    "invite_join",
                    &new_member.user.id.to_string(),
                    Some(&new_member.user.name),
                    inviter_id.as_deref(),
                    &serde_json::json!({"code": code, "delta": delta}).to_string(),
                );
            }
        }
        // Anti-raid containment is temporary; an expiry prevents a restart
        // from leaving the join gate latched forever. Manual gates are not
        // touched because only an anti-raid latch sets this marker.
        let now = chrono::Utc::now().timestamp();
        let mut raid_latched = setting_bool(
            &self.store,
            &guild_text,
            "security.anti_raid.latch_active",
            false,
        );
        if raid_latched {
            match self.store.release_expired_anti_raid_latch(&guild_text, now) {
                Ok(true) => {
                    raid_latched = false;
                    info!(%guild_text, "anti-raid containment expired and restored the prior join gate");
                }
                Ok(false) => {}
                Err(error) => {
                    warn!(%guild_text, %error, "could not release expired anti-raid containment");
                }
            }
        }
        let anti_raid_enabled = feature_enabled(
            &self.store,
            &guild_text,
            "protection.anti_raid",
            Some("security.anti_raid.enabled"),
        );
        if anti_raid_enabled {
            let threshold = self
                .store
                .get_setting(&guild_text, "security.anti_raid.joins")
                .ok()
                .flatten()
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(10)
                .clamp(2, 100);
            let window_seconds = self
                .store
                .get_setting(&guild_text, "security.anti_raid.window_seconds")
                .ok()
                .flatten()
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or(10)
                .clamp(3, 60);
            let join_count = {
                let mut joins = self.joins.lock().expect("join mutex poisoned");
                join_burst_count(
                    &mut joins,
                    &guild_text,
                    Instant::now(),
                    Duration::from_secs(window_seconds),
                    threshold,
                )
            };
            let anti_raid_policy = AntiRaidPolicy {
                join_threshold: threshold as u32,
                window_seconds,
                incident_minutes: setting_u64(
                    &self.store,
                    &guild_text,
                    "security.anti_raid.incident_minutes",
                    10,
                )
                .clamp(1, 120),
                verification: self
                    .store
                    .get_setting(&guild_text, "security.anti_raid.verification")
                    .ok()
                    .flatten()
                    .unwrap_or_else(|| "high".into()),
                alert_only: setting_bool(
                    &self.store,
                    &guild_text,
                    "security.anti_raid.alert_only",
                    false,
                ),
                pause_invites: setting_bool(
                    &self.store,
                    &guild_text,
                    "security.anti_raid.pause_invites",
                    true,
                ),
            };
            let armed = evaluate_anti_raid(&anti_raid_policy, join_count as u32, false).armed;
            if armed {
                let shadow_mode = shadow_mode_enabled(
                    self.store
                        .get_setting(&guild_text, "security.shadow_mode")
                        .ok()
                        .flatten()
                        .as_deref(),
                ) || setting_bool(
                    &self.store,
                    &guild_text,
                    "security.anti_raid.alert_only",
                    false,
                );
                let raid_decision =
                    evaluate_anti_raid(&anti_raid_policy, join_count as u32, shadow_mode);
                let shadow_mode = raid_decision.shadow_mode;
                // Bounded response: latch the existing gate and alert moderators.
                // Shadow mode and an explicit alert-only policy record/alert but
                // deliberately leave the gate unchanged.
                if raid_decision.should_contain {
                    let gate_until = now + (raid_decision.incident_minutes as i64) * 60;
                    match self.store.arm_anti_raid_latch(&guild_text, gate_until) {
                        Ok(()) => raid_latched = true,
                        Err(error) => {
                            warn!(%guild_text, %error, "could not arm anti-raid containment");
                        }
                    }
                }
                let reason = format!(
                    "Anti-raid: {threshold} joins within {window_seconds}s; {}",
                    if shadow_mode {
                        "shadow mode, no automatic containment"
                    } else if raid_decision.should_contain {
                        "join gate enabled"
                    } else {
                        "alert only; join gate unchanged"
                    }
                );
                let _ = self.store.record_case(
                    &guild_text,
                    if shadow_mode {
                        "anti_raid_shadow"
                    } else {
                        "anti_raid"
                    },
                    &new_member.user.id.to_string(),
                    "helper",
                    &reason,
                    None,
                );
                let alert_channel = setting_u64_optional(
                    &self.store,
                    &guild_text,
                    "security.anti_raid.alert_channel",
                )
                .map(ChannelId::new);
                let fallback_channel = guild_id
                    .to_partial_guild(&ctx.http)
                    .await
                    .ok()
                    .and_then(|guild| guild.system_channel_id);
                if let Some(channel_id) = alert_channel.or(fallback_channel) {
                    let _ = channel_id
                        .say(
                            &ctx.http,
                            format!(
                                "⚠️ Possible raid detected: {threshold} joins in {window_seconds}s. {} Review the recent cases.",
                                if shadow_mode {
                                    "Shadow mode is active; no automatic containment was applied."
                                } else {
                                    "The join gate was enabled."
                                }
                            ),
                        )
                        .await;
                }
            }
        }
        let gate_enabled = raid_latched
            || feature_enabled(
                &self.store,
                &guild_text,
                "protection.join_gate",
                Some("security.join_gate.enabled"),
            );
        if gate_enabled {
            let minimum_age = self
                .store
                .get_setting(&guild_text, "security.join_gate.min_age_days")
                .ok()
                .flatten()
                .and_then(|value| value.parse::<i64>().ok())
                .unwrap_or(0)
                .clamp(0, 365);
            let account_age_days = account_age_days(
                chrono::Utc::now().timestamp(),
                new_member.user.created_at().unix_timestamp(),
            );
            let raid_verification = if raid_latched {
                self.store
                    .get_setting(&guild_text, "security.anti_raid.verification")
                    .ok()
                    .flatten()
                    .unwrap_or_else(|| "high".to_string())
            } else {
                "medium".to_string()
            };
            let minimum_age = if raid_verification == "very_high" {
                minimum_age.max(7)
            } else {
                minimum_age
            };
            let require_avatar = setting_bool(
                &self.store,
                &guild_text,
                "security.join_gate.require_avatar",
                false,
            ) || (raid_latched
                && matches!(raid_verification.as_str(), "high" | "very_high"));
            let display_name = new_member
                .user
                .global_name
                .as_deref()
                .unwrap_or(&new_member.user.name)
                .to_lowercase();
            let blocked_patterns = self
                .store
                .get_setting(&guild_text, "security.join_gate.blocked_name_patterns")
                .ok()
                .flatten()
                .unwrap_or_default()
                .lines()
                .map(str::trim)
                .filter(|pattern| !pattern.is_empty())
                .map(str::to_lowercase)
                .collect::<Vec<_>>();
            let action = self
                .store
                .get_setting(&guild_text, "security.join_gate.action")
                .ok()
                .flatten()
                .unwrap_or_else(|| "quarantine".to_string());
            let gate_decision = evaluate_join_gate(
                &JoinGatePolicy {
                    minimum_account_days: minimum_age,
                    require_avatar,
                    blocked_name_patterns: blocked_patterns,
                    action,
                },
                &JoinGateObservation {
                    account_age_days,
                    has_avatar: new_member.user.avatar.is_some(),
                    display_name,
                },
            );
            if gate_decision.blocked {
                let action = gate_decision.action;
                let gate_reasons = gate_decision.reasons;
                if action == "quarantine"
                    && let Some(role_id) =
                        setting_u64_optional(&self.store, &guild_text, "security.join_gate.role_id")
                {
                    let _ = new_member.add_role(&ctx.http, RoleId::new(role_id)).await;
                }
                let reason = format!("Join gate: {}", gate_reasons.join(", "));
                let _ = self.store.record_case(
                    &guild_text,
                    "join_gate",
                    &new_member.user.id.to_string(),
                    "helper",
                    &reason,
                    None,
                );
                let log_channel = setting_u64_optional(
                    &self.store,
                    &guild_text,
                    "security.join_gate.log_channel",
                )
                .map(ChannelId::new);
                let fallback_channel = guild_id
                    .to_partial_guild(&ctx.http)
                    .await
                    .ok()
                    .and_then(|guild| guild.system_channel_id);
                if let Some(channel_id) = log_channel.or(fallback_channel) {
                    let _ = channel_id
                        .say(
                            &ctx.http,
                            format!(
                                "⚠️ <@{}> needs verification: this account is too new.",
                                new_member.user.id
                            ),
                        )
                        .await;
                }
            } else if let Some(role_id) =
                setting_u64_optional(&self.store, &guild_text, "security.join_gate.auto_role_id")
            {
                let _ = new_member.add_role(&ctx.http, RoleId::new(role_id)).await;
            }
        }
        let (welcome_enabled, welcome) = self
            .store
            .welcome_configuration(&guild_text)
            .unwrap_or((false, serde_json::json!({})));
        let welcome_claimed = welcome_enabled
            && self
                .store
                .claim_welcome_delivery(
                    &guild_text,
                    &new_member.user.id.to_string(),
                    "welcome",
                    chrono::Utc::now().timestamp(),
                    600,
                )
                .unwrap_or(false);
        if welcome_claimed {
            let member_mention = format!("<@{}>", new_member.user.id);
            let delay = welcome["delaySeconds"].as_u64().unwrap_or(0).min(300);
            if delay > 0 {
                tokio::time::sleep(Duration::from_secs(delay)).await;
            }
            if let Some(role) = welcome["autoRole"]
                .as_str()
                .and_then(|id| id.parse::<u64>().ok())
                .filter(|id| *id > 0)
            {
                let _ = new_member.add_role(&ctx.http, RoleId::new(role)).await;
            }
            let guild = guild_id.to_partial_guild(&ctx.http).await.ok();
            let server_name = guild
                .as_ref()
                .map(|g| g.name.as_str())
                .unwrap_or("this server");
            let channel = welcome["channel"]
                .as_str()
                .and_then(|id| id.parse::<u64>().ok())
                .filter(|id| *id > 0)
                .map(ChannelId::new)
                .or_else(|| guild.as_ref().and_then(|g| g.system_channel_id));
            let public_text = unified_welcome_text(
                &self.store,
                &guild_text,
                &welcome,
                "welcome",
                "👋 Welcome {member} to {server}!",
            );
            let guided = welcome["guideEnabled"].as_bool().unwrap_or_else(|| {
                setting_bool(
                    &self.store,
                    &guild_text,
                    "support.welcome.guide_enabled",
                    false,
                )
            });
            let guide = evaluate_welcome_channel(
                &serde_json::json!({
                    "channelId": channel.map(|id| id.to_string()).unwrap_or_default(),
                    "message": public_text, "steps": welcome.get("steps").cloned().unwrap_or(serde_json::json!(["rules","introductions","channels"]))
                }),
                &member_mention,
                server_name,
            );
            if let Some(channel_id) = channel {
                let mut message = CreateMessage::new()
                    .content(render_welcome_message(
                        &public_text,
                        &member_mention,
                        server_name,
                    ))
                    .allowed_mentions(
                        CreateAllowedMentions::new()
                            .everyone(false)
                            .empty_roles()
                            .users(vec![new_member.user.id]),
                    );
                if guided && guide.allowed {
                    let buttons = guide
                        .steps
                        .iter()
                        .filter_map(|step| welcome_guide_button(&guild_text, step, &welcome))
                        .collect::<Vec<_>>();
                    if !buttons.is_empty() {
                        message = message.components(vec![CreateActionRow::Buttons(buttons)]);
                    }
                }
                let delivery = channel_id.send_message(&ctx.http, message).await;
                let _ = self.store.record_activity(
                    &guild_text,
                    if delivery.is_ok() {
                        "welcome_delivery"
                    } else {
                        "welcome_delivery_failed"
                    },
                    &new_member.user.id.to_string(),
                    Some(&new_member.user.name),
                    Some(&channel_id.to_string()),
                    &serde_json::json!({"guided":guided,"sent":delivery.is_ok()}).to_string(),
                );
            }
            if welcome["sendDm"].as_bool().unwrap_or(false) {
                let text = unified_welcome_text(
                    &self.store,
                    &guild_text,
                    &welcome,
                    "dm",
                    "Hello {member}, welcome to {server}!",
                );
                let _ = new_member
                    .user
                    .direct_message(
                        &ctx.http,
                        CreateMessage::new()
                            .content(render_member_message(&text, &member_mention, server_name))
                            .allowed_mentions(
                                CreateAllowedMentions::new()
                                    .everyone(false)
                                    .empty_roles()
                                    .empty_users(),
                            ),
                    )
                    .await;
            }
        }
    }

    async fn guild_member_removal(
        &self,
        ctx: Context,
        guild_id: serenity::all::GuildId,
        user: serenity::all::User,
        _member_data_if_available: Option<serenity::all::Member>,
    ) {
        let day = chrono::Utc::now().format("%Y-%m-%d").to_string();
        let guild_text = guild_id.to_string();
        let _ = self.store.record_leave(&guild_text, &day);
        if feature_enabled(&self.store, &guild_text, "management.audit", None) {
            let detail = serde_json::json!({
                "event": "member_leave",
                "contentAvailable": false,
            })
            .to_string();
            let _ = self.store.record_activity(
                &guild_text,
                "member_leave",
                &user.id.to_string(),
                Some(&user.name),
                None,
                &detail,
            );
            if let Some(raw_channel) =
                setting_string(&self.store, &guild_text, "management.audit.log_channel")
                    .filter(|value| !value.trim().is_empty())
                && let Ok(log_channel) = raw_channel.parse::<u64>()
            {
                let _ = ChannelId::new(log_channel)
                    .say(&ctx.http, format!("Audit: <@{}> left the server.", user.id))
                    .await;
            }
        }
        let (welcome_enabled, welcome) = self
            .store
            .welcome_configuration(&guild_text)
            .unwrap_or((false, serde_json::json!({})));
        if welcome_enabled && welcome["farewellMessage"].as_str() != Some("") {
            let text = unified_welcome_text(
                &self.store,
                &guild_text,
                &welcome,
                "farewell",
                "Goodbye {member}. We hope to see you again!",
            );
            let guild = guild_id.to_partial_guild(&ctx.http).await.ok();
            let server_name = guild
                .as_ref()
                .map(|g| g.name.as_str())
                .unwrap_or("this server");
            let channel = welcome["farewellChannel"]
                .as_str()
                .and_then(|id| id.parse::<u64>().ok())
                .filter(|id| *id > 0)
                .map(ChannelId::new)
                .or_else(|| guild.as_ref().and_then(|g| g.system_channel_id));
            if let Some(channel_id) = channel {
                let _ = channel_id
                    .send_message(
                        &ctx.http,
                        CreateMessage::new()
                            .content(render_member_message(&text, &user.name, server_name))
                            .allowed_mentions(
                                CreateAllowedMentions::new()
                                    .everyone(false)
                                    .empty_roles()
                                    .empty_users(),
                            ),
                    )
                    .await;
            }
        }
        if let Ok(deleted) = self
            .store
            .delete_member_voluntary_data(&guild_text, &user.id.to_string())
        {
            tracing::debug!(
                guild_id = %guild_id,
                user_id = %user.id,
                ?deleted,
                "removed member voluntary state"
            );
        }
    }

    async fn auto_moderation_action_execution(
        &self,
        _ctx: Context,
        execution: serenity::all::ActionExecution,
    ) {
        let reason = format!(
            "Discord AutoMod rule {} ({:?}){}",
            execution.rule_id,
            execution.trigger_type,
            execution
                .matched_keyword
                .as_deref()
                .map(|keyword| format!("; matched keyword: {keyword}"))
                .unwrap_or_default()
        );
        let _ = self.store.record_case(
            &execution.guild_id.to_string(),
            "automod",
            &execution.user_id.to_string(),
            "discord-automod",
            &reason,
            None,
        );
    }

    async fn guild_audit_log_entry_create(
        &self,
        ctx: Context,
        entry: serenity::all::AuditLogEntry,
        guild_id: serenity::all::GuildId,
    ) {
        let guild_text = guild_id.to_string();
        if !feature_enabled(&self.store, &guild_text, "management.audit", None) {
            return;
        }
        let enabled = self
            .store
            .get_setting(&guild_text, "security.anti_nuke.enabled")
            .ok()
            .flatten()
            .is_some_and(|value| value == "true");
        if !enabled || !is_destructive_audit_action(entry.action) {
            return;
        }
        let threshold = self
            .store
            .get_setting(&guild_text, "security.anti_nuke.actions")
            .ok()
            .flatten()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(3)
            .clamp(2, 25);
        let window_seconds = self
            .store
            .get_setting(&guild_text, "security.anti_nuke.window_seconds")
            .ok()
            .flatten()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(10)
            .clamp(3, 60);
        let executor = entry.user_id.to_string();
        let armed = {
            let mut events = self.nuke_events.lock().expect("anti-nuke mutex poisoned");
            join_burst_armed(
                &mut events,
                &format!("{guild_text}:{executor}"),
                Instant::now(),
                Duration::from_secs(window_seconds),
                threshold,
            )
        };
        let action = format!("audit action {}", entry.action.num());
        let reason = format!("Anti-nuke audit: {action} by <@{executor}>");
        let _ = self.store.record_case(
            &guild_text,
            "anti_nuke_audit",
            &executor,
            "discord-audit-log",
            &reason,
            None,
        );
        if !armed {
            return;
        }
        let audit_config = serde_json::json!({
            "threshold": threshold as i64,
            "windowSeconds": window_seconds as i64,
            "incidentMinutes": setting_u64(
                &self.store,
                &guild_text,
                "security.anti_nuke.incident_minutes",
                10,
            )
            .clamp(1, 120) as i64,
            "shadowMode": shadow_mode_enabled(
                self.store
                    .get_setting(&guild_text, "security.shadow_mode")
                    .ok()
                    .flatten()
                    .as_deref(),
            ),
            "logChannel": setting_string(
                &self.store,
                &guild_text,
                "management.audit.log_channel",
            )
            .unwrap_or_default(),
            "includeContent": setting_bool(
                &self.store,
                &guild_text,
                "management.audit.include_content",
                false,
            ),
        });
        let audit_decision = evaluate_audit(&audit_config, threshold as i64);
        let configured_log_channel = audit_decision
            .log_channel_id
            .as_deref()
            .and_then(|value| value.parse::<u64>().ok())
            .map(ChannelId::new);
        let fallback_log_channel = if configured_log_channel.is_none() {
            guild_id
                .to_partial_guild(&ctx.http)
                .await
                .ok()
                .and_then(|guild| guild.system_channel_id)
        } else {
            None
        };
        let audit_alert_channel = configured_log_channel.or(fallback_log_channel);
        let shadow_mode = audit_decision.shadow_mode;
        if shadow_mode {
            let _ = self.store.record_case(
                &guild_text,
                "anti_nuke_shadow",
                &executor,
                "helper",
                &format!(
                    "{threshold} destructive actions in {window_seconds}s; shadow mode, no automatic containment"
                ),
                None,
            );
            if let Some(channel_id) = audit_alert_channel {
                let _ = channel_id
                    .say(
                        &ctx.http,
                        format!(
                            "🚨 Possible nuke attack: <@{executor}> performed {threshold} destructive actions in {window_seconds}s. Shadow mode is active; no automatic containment was applied."
                        ),
                    )
                    .await;
            }
            return;
        }
        // Containment is intentionally reversible and non-destructive. It uses
        // the same durable latch as anti-raid so overlapping incidents keep the
        // gate closed until the latest deadline, then restore its prior state.
        let gate_until = anti_nuke_containment_deadline(
            Utc::now().timestamp(),
            audit_decision.incident_minutes as u64,
        );
        let contained = match self.store.arm_anti_raid_latch(&guild_text, gate_until) {
            Ok(()) => true,
            Err(error) => {
                warn!(%guild_text, %error, "could not arm anti-nuke containment");
                false
            }
        };
        let _ = self.store.record_case(
            &guild_text,
            "anti_nuke",
            &executor,
            "helper",
            &if contained {
                format!(
                    "{threshold} destructive actions in {window_seconds}s; join gate enabled for {} minutes before automatic restoration",
                    audit_decision.incident_minutes
                )
            } else {
                format!(
                    "{threshold} destructive actions in {window_seconds}s; containment could not be armed"
                )
            },
            None,
        );
        if let Some(channel_id) = audit_alert_channel {
            let _ = channel_id
                .say(
                    &ctx.http,
                    if contained {
                        format!(
                            "🚨 Possible nuke attack: <@{executor}> performed {threshold} destructive actions in {window_seconds}s. The join gate was enabled for {} minutes and will then restore its earlier state; review the Audit Log before removing roles.",
                            audit_decision.incident_minutes
                        )
                    } else {
                        format!(
                            "🚨 Possible nuke attack: <@{executor}> performed {threshold} destructive actions in {window_seconds}s. The Helper could not arm temporary containment; review the Audit Log immediately."
                        )
                    },
                )
                .await;
        }
    }

    async fn reaction_add(&self, ctx: Context, reaction: serenity::all::Reaction) {
        let Some(guild_id) = reaction.guild_id else {
            return;
        };
        if !feature_enabled(
            &self.store,
            &guild_id.to_string(),
            "community.starboard",
            Some("feature.community.starboard"),
        ) {
            return;
        }
        if reaction.user_id == ctx.http.get_current_user().await.ok().map(|user| user.id) {
            return;
        }
        let serenity::all::ReactionType::Unicode(emoji) = &reaction.emoji else {
            return;
        };
        let configured_emoji = setting_string(
            &self.store,
            &guild_id.to_string(),
            "community.starboard.emoji",
        )
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "⭐".to_string());
        if emoji != &configured_emoji && !(configured_emoji == "⭐" && emoji == "🌟") {
            return;
        }
        let ignored_channels = setting_string(
            &self.store,
            &guild_id.to_string(),
            "community.starboard.ignored_channels",
        )
        .unwrap_or_default();
        if ignored_channels
            .split(',')
            .map(str::trim)
            .any(|channel| channel == reaction.channel_id.to_string())
        {
            return;
        }
        let Ok(Some(raw_board_id)) = self
            .store
            .get_setting(&guild_id.to_string(), "community.starboard.channel_id")
        else {
            return;
        };
        let Ok(board_id) = raw_board_id.parse::<u64>() else {
            return;
        };
        if board_id == reaction.channel_id.get() {
            return;
        }
        let Ok(users) = reaction
            .channel_id
            .reaction_users(
                &ctx.http,
                reaction.message_id,
                reaction.emoji.clone(),
                Some(100),
                None,
            )
            .await
        else {
            return;
        };
        let original = match reaction
            .channel_id
            .message(&ctx.http, reaction.message_id)
            .await
        {
            Ok(message) => message,
            Err(_) => return,
        };
        let guild_text = guild_id.to_string();
        let policy = starboard_policy_for_store(&self.store, &guild_text);
        let author_role_ids = guild_id
            .member(&ctx.http, original.author.id)
            .await
            .map(|member| {
                member
                    .roles
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let mut decision = evaluate_starboard(
            &policy,
            &StarboardObservation {
                source_channel_id: reaction.channel_id.to_string(),
                author_id: original.author.id.to_string(),
                reactor_ids: users.iter().map(|user| user.id.to_string()).collect(),
                author_role_ids,
                has_attachments: !original.attachments.is_empty(),
            },
        );
        if decision.ignored {
            return;
        }
        let normal_reactions = original
            .reactions
            .iter()
            .find(|item| item.reaction_type == reaction.emoji)
            .map(|item| item.count_details.normal)
            .unwrap_or(users.len() as u64);
        decision.count = decision.count.max(starboard_reaction_count(
            normal_reactions,
            users.iter().any(|user| user.id == original.author.id),
            policy.allow_self_star,
        ));
        decision.should_publish = decision.count >= decision.threshold;
        let count = decision.count as i64;
        let link = format!(
            "https://discord.com/channels/{}/{}/{}",
            guild_id, reaction.channel_id, reaction.message_id
        );
        if !decision.should_publish {
            if let Ok(Some(entry)) = self
                .store
                .star_entry(&guild_id.to_string(), &reaction.message_id.to_string())
            {
                if let Ok(message_id) = entry.starboard_message_id.parse::<u64>() {
                    let _ = serenity::all::ChannelId::new(board_id)
                        .delete_message(&ctx.http, serenity::all::MessageId::new(message_id))
                        .await;
                }
                let _ = self
                    .store
                    .delete_star_entry(&guild_id.to_string(), &reaction.message_id.to_string());
            }
            return;
        }
        let content =
            starboard_message_content(&policy, &configured_emoji, count, &original, &link);
        if let Ok(Some(entry)) = self
            .store
            .star_entry(&guild_id.to_string(), &reaction.message_id.to_string())
        {
            if let Ok(message_id) = entry.starboard_message_id.parse::<u64>()
                && starboard_display::publish(
                    &ctx,
                    ChannelId::new(board_id),
                    Some(MessageId::new(message_id)),
                    &original,
                    count,
                    &link,
                    &content,
                )
                .await
                .is_ok()
            {
                let _ = self.store.upsert_star_entry(
                    &guild_id.to_string(),
                    &reaction.message_id.to_string(),
                    &entry.starboard_message_id,
                    count,
                );
            }
        } else if let Ok(message) = starboard_display::publish(
            &ctx,
            ChannelId::new(board_id),
            None,
            &original,
            count,
            &link,
            &content,
        )
        .await
        {
            let _ = self.store.upsert_star_entry(
                &guild_id.to_string(),
                &reaction.message_id.to_string(),
                &message.id.to_string(),
                count,
            );
        }
    }

    async fn message_delete(
        &self,
        ctx: Context,
        channel_id: ChannelId,
        deleted_message_id: serenity::all::MessageId,
        guild_id: Option<serenity::all::GuildId>,
    ) {
        let Some(guild_id) = guild_id else {
            return;
        };
        let guild_text = guild_id.to_string();
        if feature_enabled(&self.store, &guild_text, "management.audit", None) {
            let detail = serde_json::json!({
                "messageId": deleted_message_id.to_string(),
                "channelId": channel_id.to_string(),
                "contentAvailable": false,
            })
            .to_string();
            let _ = self.store.record_activity(
                &guild_text,
                "message_delete",
                "unknown",
                None,
                Some("unknown"),
                &detail,
            );
            if let Some(raw_channel) =
                setting_string(&self.store, &guild_text, "management.audit.log_channel")
                    .filter(|value| !value.trim().is_empty())
                && let Ok(log_channel) = raw_channel.parse::<u64>()
            {
                let _ = ChannelId::new(log_channel)
                    .say(
                        &ctx.http,
                        format!(
                            "Audit: message {} deleted from <#{}>. Content was not available.",
                            deleted_message_id, channel_id
                        ),
                    )
                    .await;
            }
        }
        let Ok(Some(entry)) = self
            .store
            .star_entry(&guild_text, &deleted_message_id.to_string())
        else {
            return;
        };
        if let Some(board_id) =
            setting_string(&self.store, &guild_text, "community.starboard.channel_id")
                .and_then(|value| value.parse::<u64>().ok())
            && let Ok(starboard_message_id) = entry.starboard_message_id.parse::<u64>()
        {
            let _ = ChannelId::new(board_id)
                .delete_message(
                    &ctx.http,
                    serenity::all::MessageId::new(starboard_message_id),
                )
                .await;
        }
        let _ = self
            .store
            .delete_star_entry(&guild_text, &deleted_message_id.to_string());
    }

    async fn message_delete_bulk(
        &self,
        ctx: Context,
        channel_id: ChannelId,
        deleted_message_ids: Vec<serenity::all::MessageId>,
        guild_id: Option<serenity::all::GuildId>,
    ) {
        let Some(guild_id) = guild_id else {
            return;
        };
        let guild_text = guild_id.to_string();
        if feature_enabled(&self.store, &guild_text, "management.audit", None) {
            let detail = serde_json::json!({
                "channelId": channel_id.to_string(),
                "count": deleted_message_ids.len(),
                "contentAvailable": false,
            })
            .to_string();
            let _ = self.store.record_activity(
                &guild_text,
                "message_delete_bulk",
                "unknown",
                None,
                Some("unknown"),
                &detail,
            );
            if let Some(raw_channel) =
                setting_string(&self.store, &guild_text, "management.audit.log_channel")
                    .filter(|value| !value.trim().is_empty())
                && let Ok(log_channel) = raw_channel.parse::<u64>()
            {
                let _ = ChannelId::new(log_channel)
                    .say(
                        &ctx.http,
                        format!(
                            "Audit: {} messages deleted in <#{}>. Content was not available.",
                            deleted_message_ids.len(),
                            channel_id
                        ),
                    )
                    .await;
            }
        }
        let board_id = setting_string(&self.store, &guild_text, "community.starboard.channel_id")
            .and_then(|value| value.parse::<u64>().ok())
            .map(serenity::all::ChannelId::new);
        for deleted_message_id in deleted_message_ids {
            let Ok(Some(entry)) = self
                .store
                .star_entry(&guild_text, &deleted_message_id.to_string())
            else {
                continue;
            };
            if let Some(board_id) = board_id
                && let Ok(starboard_message_id) = entry.starboard_message_id.parse::<u64>()
            {
                let _ = board_id
                    .delete_message(
                        &ctx.http,
                        serenity::all::MessageId::new(starboard_message_id),
                    )
                    .await;
            }
            let _ = self
                .store
                .delete_star_entry(&guild_text, &deleted_message_id.to_string());
        }
    }

    async fn message_update(
        &self,
        ctx: Context,
        _old: Option<serenity::all::Message>,
        new: Option<serenity::all::Message>,
        event: MessageUpdateEvent,
    ) {
        let Some(guild_id) = event.guild_id else {
            return;
        };
        let guild_text = guild_id.to_string();
        let author_id = event
            .author
            .as_ref()
            .map(|author| author.id.to_string())
            .or_else(|| new.as_ref().map(|message| message.author.id.to_string()))
            .unwrap_or_else(|| "unknown".into());
        let author_tag = event.author.as_ref().map(|author| author.tag());
        if feature_enabled(&self.store, &guild_text, "management.audit", None) {
            let detail = serde_json::json!({
                "messageId": event.id.to_string(),
                "channelId": event.channel_id.to_string(),
                "contentAvailable": event.content.is_some(),
                "embedsChanged": event.embeds.is_some(),
                "attachmentsChanged": event.attachments.is_some(),
                "editedTimestamp": event.edited_timestamp.as_ref().map(ToString::to_string),
            })
            .to_string();
            let _ = self.store.record_activity(
                &guild_text,
                "message_edit",
                &author_id,
                author_tag.as_deref(),
                Some(&author_id),
                &detail,
            );
            if let Some(raw_channel) =
                setting_string(&self.store, &guild_text, "management.audit.log_channel")
                    .filter(|value| !value.trim().is_empty())
                && let Ok(log_channel) = raw_channel.parse::<u64>()
            {
                let content = if setting_bool(
                    &self.store,
                    &guild_text,
                    "management.audit.include_content",
                    false,
                ) {
                    event
                        .content
                        .as_deref()
                        .map(|value| format!(" Content: {}", truncate(value, 900)))
                        .unwrap_or_default()
                } else {
                    String::new()
                };
                let _ = ChannelId::new(log_channel)
                    .say(
                        &ctx.http,
                        format!(
                            "Audit: message {} edited in <#{}> by <@{}>.{}",
                            event.id, event.channel_id, author_id, content
                        ),
                    )
                    .await;
            }
        }

        self.reconcile_starboard_entry(&ctx, guild_id, event.channel_id, event.id, new.as_ref())
            .await;

        // Edited messages must pass the same scam evaluator as new messages.
        // Discord may omit the content from the gateway event, so only act
        // when a bounded content value is actually available.
        let Some(content) = event
            .content
            .as_deref()
            .or_else(|| new.as_ref().map(|message| message.content.as_str()))
        else {
            return;
        };
        if !feature_enabled(&self.store, &guild_text, "protection.antiscam", None) {
            return;
        }
        let policy = scam_policy_for_store(&self.store, &guild_text);
        let author = event
            .author
            .as_ref()
            .or_else(|| new.as_ref().map(|message| &message.author));
        if author.is_some_and(|author| author.bot) {
            return;
        }
        let snapshot_roles = edit_member_roles(&event, new.as_ref());
        let edit_role_ids = if let Some(roles) = snapshot_roles {
            roles.iter().map(ToString::to_string).collect::<Vec<_>>()
        } else if !policy.ignored_roles.is_empty() {
            let Some(user_id) = author.map(|author| author.id) else {
                return;
            };
            // Cache is intentionally disabled. Never enforce an ignored-role
            // policy against an invented empty member snapshot.
            let Ok(member) = guild_id.member(&ctx.http, user_id).await else {
                return;
            };
            member.roles.iter().map(ToString::to_string).collect()
        } else {
            Vec::new()
        };
        let decision = evaluate_scam_with_roles(
            &policy,
            &event.channel_id.to_string(),
            &edit_role_ids,
            content,
        );
        if decision.ignored || decision.matched.is_empty() {
            return;
        }
        let reason = format!(
            "Scam protection matched after edit: {}",
            decision.matched.join(", ")
        );
        let _ = self.store.record_case(
            &guild_text,
            "anti-scam",
            &author_id,
            &author_id,
            &reason,
            None,
        );
        if let Some(raw_channel) =
            setting_string(&self.store, &guild_text, "security.antiscam.log_channel")
                .filter(|value| !value.trim().is_empty())
            && let Ok(channel) = raw_channel.parse::<u64>()
        {
            let _ = ChannelId::new(channel)
                .say(
                    &ctx.http,
                    format!("Scam protection: <@{author_id}> — {reason} (edited message)"),
                )
                .await;
        }
        if decision.should_act {
            if decision.should_delete {
                let _ = event.channel_id.delete_message(&ctx.http, event.id).await;
            }
            if decision.timeout_seconds > 0
                && let Ok(user_id) = author_id.parse::<u64>()
            {
                let until = (chrono::Utc::now()
                    + chrono::Duration::seconds(decision.timeout_seconds as i64))
                .to_rfc3339();
                let _ = guild_id
                    .edit_member(
                        &ctx.http,
                        serenity::all::UserId::new(user_id),
                        serenity::all::EditMember::new().disable_communication_until(until),
                    )
                    .await;
            }
        }
    }

    async fn reaction_remove(&self, ctx: Context, reaction: serenity::all::Reaction) {
        // The board reconciler reads the current reaction users, so the same
        // path safely handles additions, removals and Discord retries.
        self.reaction_add(ctx, reaction).await;
    }

    async fn message(&self, ctx: Context, message: serenity::all::Message) {
        if message.author.bot {
            return;
        }
        let Some(guild_id) = message.guild_id else {
            return;
        };
        let guild_text = guild_id.to_string();
        let user_text = message.author.id.to_string();
        let _ = self.store.record_message(
            &guild_text,
            &chrono::Utc::now().format("%Y-%m-%d").to_string(),
        );
        if feature_enabled(&self.store, &guild_text, "community.levels", None) {
            let ignored_channels = setting_string(
                &self.store,
                &guild_text,
                "community.levels.ignored_channels",
            )
            .unwrap_or_default();
            let channel_ignored = ignored_channels
                .split(',')
                .any(|channel| channel.trim() == message.channel_id.to_string());
            if !channel_ignored {
                let cooldown = setting_u64(
                    &self.store,
                    &guild_text,
                    "community.levels.cooldown_seconds",
                    60,
                )
                .clamp(0, 3_600);
                let xp_key = format!("{guild_text}:{user_text}");
                let now = Instant::now();
                let should_award = {
                    let mut awarded = self.xp_awarded_at.lock().expect("xp mutex poisoned");
                    let ready = awarded
                        .get(&xp_key)
                        .is_none_or(|at| now.duration_since(*at) >= Duration::from_secs(cooldown));
                    if ready {
                        awarded.insert(xp_key, now);
                    }
                    ready
                };
                if should_award {
                    let before = self.store.level_for(&guild_text, &user_text).unwrap_or(0);
                    let event_key = format!("message:{}", message.id);
                    let decision = evaluate_levels(
                        &levels_config_for_store(&self.store, &guild_text),
                        "message",
                        &message.channel_id.to_string(),
                        &event_key,
                        true,
                        0,
                        before,
                    );
                    let award = if decision.allowed {
                        match self.store.add_xp_event(
                            &guild_text,
                            &user_text,
                            &event_key,
                            "message",
                            decision.amount,
                            Utc::now().timestamp_millis(),
                        ) {
                            Ok(Some(after)) => Some(after),
                            Ok(None) => {
                                // The event was already applied by an earlier
                                // delivery; its announcements were already sent.
                                None
                            }
                            Err(error) => {
                                warn!(%guild_id, user = %message.author.id, %error, "failed to award message XP");
                                None
                            }
                        }
                    } else {
                        None
                    };
                    if let Some(after) = award {
                        self.announce_achievement_unlocks(
                            &ctx,
                            guild_id,
                            &user_text,
                            after,
                            Some(message.channel_id),
                        )
                        .await;
                        let before_level = before / 100 + 1;
                        let after_level = after / 100 + 1;
                        if after_level > before_level {
                            self.apply_level_rewards(&ctx, guild_id, &user_text, after_level)
                                .await;
                            let text = setting_string(
                                &self.store,
                                &guild_text,
                                "community.levels.announce_template",
                            )
                            .unwrap_or_else(|| "{member} reached level {level}!".to_string())
                            .replace("{member}", &format!("<@{}>", message.author.id))
                            .replace("{level}", &after_level.to_string())
                            .replace("{server}", "this server");
                            let channel = setting_u64_optional(
                                &self.store,
                                &guild_text,
                                "community.levels.announce_channel",
                            )
                            .map(ChannelId::new)
                            .unwrap_or(message.channel_id);
                            let mut announcement =
                                CreateMessage::new().content(&text).allowed_mentions(
                                    CreateAllowedMentions::new().users([message.author.id]),
                                );
                            if setting_bool(
                                &self.store,
                                &guild_text,
                                "community.levels.banner_enabled",
                                false,
                            ) {
                                let premium = matches!(
                                    self.effective_plan(&user_text, Some(&guild_text)).await,
                                    Plan::Premium { .. }
                                );
                                let card = rank_card::config_for_plan(
                                    self.store
                                        .get_setting(&guild_text, "community.rank_card")
                                        .ok()
                                        .flatten(),
                                    premium,
                                );
                                let colour = u32::from_str_radix(
                                    card.primary_color.trim_start_matches('#'),
                                    16,
                                )
                                .unwrap_or(0x8EE5D2);
                                let mut embed = CreateEmbed::new()
                                    .title(format!(
                                        "{} · Level {}",
                                        message.author.name, after_level
                                    ))
                                    .description(format!("{} XP", after))
                                    .thumbnail(message.author.face())
                                    .colour(Colour::new(colour));
                                if let Some(bytes) = card
                                    .background_preset
                                    .as_deref()
                                    .and_then(rank_card::preset_png)
                                {
                                    announcement = announcement.add_file(CreateAttachment::bytes(
                                        bytes,
                                        "level-up-banner.png",
                                    ));
                                    embed = embed.image("attachment://level-up-banner.png");
                                }
                                announcement = announcement.embed(embed);
                            }
                            if let Err(error) = channel.send_message(&ctx.http, announcement).await
                            {
                                warn!(%guild_id, %error, "failed to send level-up announcement");
                            }
                        }
                    }
                }
            }
        }
        if feature_enabled(&self.store, &guild_text, "utility.reminders", None)
            && let Ok(Some(afk)) = self.store.get_afk(&guild_text, &user_text)
        {
            let _ = self.store.clear_afk(&guild_text, &user_text);
            let _ = message
                .channel_id
                .say(
                    &ctx.http,
                    format!(
                        "Welcome back, <@{}>. Your AFK status was removed.",
                        afk.user_id
                    ),
                )
                .await;
        }
        if feature_enabled(&self.store, &guild_text, "management.custom_commands", None) {
            let staff_only = setting_bool(
                &self.store,
                &guild_text,
                "management.custom_commands.staff_only",
                false,
            );
            let ignored_channels = setting_string(
                &self.store,
                &guild_text,
                "management.custom_commands.ignored_channels",
            )
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .collect::<Vec<_>>();
            let config = serde_json::json!({
                "triggerPrefix": setting_string(
                    &self.store,
                    &guild_text,
                    "management.custom_commands.trigger_prefix",
                )
                .unwrap_or_else(|| "!".into()),
                "ignoredChannels": ignored_channels,
                "staffOnly": staff_only,
                "maxResponseLength": setting_u64(
                    &self.store,
                    &guild_text,
                    "management.custom_commands.max_response_length",
                    1_000,
                ),
            });
            let actor_is_staff = custom_command_is_staff(
                message
                    .member
                    .as_ref()
                    .and_then(|member| member.permissions),
            );
            let server_name = format!("server {guild_text}");
            let preview = evaluate_custom_command(
                &config,
                &message.content,
                &message.channel_id.to_string(),
                actor_is_staff,
                None,
                &message.author.id.to_string(),
                &server_name,
            );
            if preview.reason_code == "tag_not_found"
                && let Ok(Some(tag)) = self.store.get_tag(&guild_text, &preview.command_name)
            {
                let decision = evaluate_custom_command(
                    &config,
                    &message.content,
                    &message.channel_id.to_string(),
                    actor_is_staff,
                    Some(&tag.content),
                    &message.author.id.to_string(),
                    &server_name,
                );
                if decision.allowed
                    && message
                        .channel_id
                        .send_message(
                            &ctx.http,
                            CreateMessage::new()
                                .content(&decision.response)
                                .allowed_mentions(
                                    CreateAllowedMentions::new()
                                        .everyone(false)
                                        .empty_users()
                                        .empty_roles()
                                        .replied_user(false),
                                ),
                        )
                        .await
                        .is_ok()
                {
                    let detail = serde_json::json!({
                        "command": decision.command_name,
                        "messageId": message.id.to_string(),
                        "channelId": message.channel_id.to_string(),
                        "staffOnly": staff_only,
                    })
                    .to_string();
                    let _ = self.store.record_activity(
                        &guild_text,
                        "custom_command",
                        &user_text,
                        Some(&message.author.name),
                        Some(&message.channel_id.to_string()),
                        &detail,
                    );
                }
            }
        }
        if feature_enabled(&self.store, &guild_text, "protection.antispam", None) {
            let policy = anti_spam_policy_for_store(&self.store, &guild_text);
            let (link_count, uppercase_letters, letter_count) =
                anti_spam_content_metrics(&message.content);
            let window_seconds = policy.window_seconds;
            let now = Instant::now();
            let key = format!("{}:{}", guild_id, message.author.id);
            let count = {
                let mut states = self.spam.lock().expect("spam mutex poisoned");
                let window = states.entry(key.clone()).or_default();
                while window
                    .front()
                    .is_some_and(|at| now.duration_since(*at) > Duration::from_secs(window_seconds))
                {
                    window.pop_front();
                }
                window.push_back(now);
                window.len()
            };
            let normalized = message.content.trim().to_lowercase();
            let duplicate_count = {
                let mut messages = self
                    .duplicate_messages
                    .lock()
                    .expect("duplicate spam mutex poisoned");
                let recent = messages.entry(key.clone()).or_default();
                while recent.front().is_some_and(|(at, _)| {
                    now.duration_since(*at) > Duration::from_secs(window_seconds)
                }) {
                    recent.pop_front();
                }
                recent.push_back((now, normalized.clone()));
                recent
                    .iter()
                    .filter(|(_, content)| content == &normalized)
                    .count()
            };
            let role_ids = message
                .member
                .as_ref()
                .map(|member| member.roles.iter().map(ToString::to_string).collect())
                .unwrap_or_default();
            let decision = evaluate_anti_spam(
                &policy,
                &AntiSpamObservation {
                    channel_id: message.channel_id.to_string(),
                    role_ids,
                    message_count: count as u32,
                    duplicate_count: duplicate_count as u32,
                    mention_count: message.mentions.len() as u32,
                    link_count,
                    uppercase_letters,
                    letter_count,
                },
            );
            if !decision.ignored && !decision.matched.is_empty() {
                let should_emit = {
                    let mut actions = self
                        .spam_action_at
                        .lock()
                        .expect("spam action mutex poisoned");
                    actions.retain(|_, at| {
                        now.duration_since(*at)
                            < Duration::from_secs(window_seconds.saturating_mul(2))
                    });
                    let allowed = actions.get(&key).is_none_or(|at| {
                        now.duration_since(*at) >= Duration::from_secs(window_seconds)
                    });
                    if allowed {
                        actions.insert(key.clone(), now);
                    }
                    allowed
                };
                if should_emit {
                    let _ = self.store.record_case(
                        &guild_id.to_string(),
                        "anti-spam",
                        &message.author.id.to_string(),
                        &message.author.id.to_string(),
                        &format!(
                            "Spam detected ({signals}): {count} messages/{window_seconds}s, {duplicate_count} duplicates, {mention_count} mentions, {link_count} links, {uppercase_letters}/{letter_count} uppercase letters",
                            signals = decision.matched.join(", "),
                            mention_count = message.mentions.len(),
                        ),
                        None,
                    );
                    if let Some(raw_channel) =
                        setting_string(&self.store, &guild_text, "security.antispam.log_channel")
                            .filter(|value| !value.trim().is_empty())
                        && let Ok(channel) = raw_channel.parse::<u64>()
                    {
                        let _ = ChannelId::new(channel)
                            .say(
                                &ctx.http,
                                anti_spam_log_message(
                                    &message.author.id.to_string(),
                                    &decision.matched,
                                    decision.should_act,
                                ),
                            )
                            .await;
                    }
                    if decision.should_act {
                        if decision.should_delete {
                            let _ = message.delete(&ctx.http).await;
                        }
                        if decision.timeout_seconds > 0 {
                            let until = chrono::Utc::now()
                                + chrono::Duration::seconds(decision.timeout_seconds as i64);
                            match guild_id
                                .edit_member(
                                    &ctx.http,
                                    message.author.id,
                                    serenity::all::EditMember::new()
                                        .disable_communication_until(until.to_rfc3339()),
                                )
                                .await
                            {
                                Ok(_) => {
                                    let payload = serde_json::json!({
                                        "expected_until_unix": until.timestamp(),
                                    });
                                    if let Err(error) = self.store.schedule_typed(
                                        &guild_text,
                                        "anti_spam_untimeout",
                                        &message.author.id.to_string(),
                                        until.timestamp_millis() + 1_500,
                                        &payload.to_string(),
                                    ) {
                                        warn!(
                                            %error,
                                            guild_id = %guild_text,
                                            member_id = %message.author.id,
                                            "failed to schedule anti-spam timeout release"
                                        );
                                    }
                                }
                                Err(error) => warn!(
                                    %error,
                                    guild_id = %guild_text,
                                    member_id = %message.author.id,
                                    "failed to apply anti-spam timeout"
                                ),
                            }
                        }
                        let warning_delivery = setting_string(
                            &self.store,
                            &guild_text,
                            "security.antispam.warning_delivery",
                        );
                        let warning_targets =
                            anti_spam_warning_targets(warning_delivery.as_deref());
                        let explanation = anti_spam_member_explanation(&decision.matched);
                        if warning_targets.chat
                            && let Err(error) = message
                                .channel_id
                                .say(
                                    &ctx.http,
                                    format!(
                                        "⚠️ <@{}>, please slow down. {explanation} The configured moderation action was applied.",
                                        message.author.id
                                    ),
                                )
                                .await
                        {
                            warn!(
                                %error,
                                guild_id = %guild_text,
                                member_id = %message.author.id,
                                "failed to send anti-spam warning in the channel"
                            );
                        }
                        if warning_targets.dm
                            && let Err(error) = message
                                .author
                                .direct_message(
                                    &ctx.http,
                                    CreateMessage::new().content(format!(
                                        "⚠️ You received an anti-spam warning from Vozen Helper. {explanation} The configured moderation action was applied."
                                    )),
                                )
                                .await
                        {
                            // Members can disable DMs from server members. The moderation
                            // action must remain successful even when Discord rejects this
                            // optional notification.
                            warn!(
                                %error,
                                guild_id = %guild_text,
                                member_id = %message.author.id,
                                "failed to send anti-spam warning by direct message"
                            );
                        }
                    }
                }
            }
        }
        if feature_enabled(&self.store, &guild_text, "protection.antiscam", None) {
            let policy = scam_policy_for_store(&self.store, &guild_text);
            let role_ids = message
                .member
                .as_ref()
                .map(|member| {
                    member
                        .roles
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let decision = evaluate_scam_with_roles(
                &policy,
                &message.channel_id.to_string(),
                &role_ids,
                &message.content,
            );
            if !decision.ignored && !decision.matched.is_empty() {
                let reason = format!("Scam protection matched: {}", decision.matched.join(", "));
                let _ = self.store.record_case(
                    &guild_text,
                    "anti-scam",
                    &message.author.id.to_string(),
                    &message.author.id.to_string(),
                    &reason,
                    None,
                );
                if let Some(raw_channel) =
                    setting_string(&self.store, &guild_text, "security.antiscam.log_channel")
                        .filter(|value| !value.trim().is_empty())
                    && let Ok(channel) = raw_channel.parse::<u64>()
                {
                    let _ = ChannelId::new(channel)
                        .say(
                            &ctx.http,
                            format!(
                                "Scam protection: <@{}> — {} ({})",
                                message.author.id,
                                reason,
                                if decision.should_act {
                                    "action"
                                } else {
                                    "monitoring"
                                }
                            ),
                        )
                        .await;
                }
                if decision.should_act {
                    if decision.should_delete {
                        let _ = message.delete(&ctx.http).await;
                    }
                    if decision.timeout_seconds > 0 {
                        let until = (chrono::Utc::now()
                            + chrono::Duration::seconds(decision.timeout_seconds as i64))
                        .to_rfc3339();
                        let _ = guild_id
                            .edit_member(
                                &ctx.http,
                                message.author.id,
                                serenity::all::EditMember::new().disable_communication_until(until),
                            )
                            .await;
                    }
                }
            }
        }
        if feature_enabled(&self.store, &guild_text, "management.workflows", None)
            && let Ok(workflows) = self.store.active_workflows(&guild_text, "message")
        {
            let policy = WorkflowPolicy {
                max_reply_length: setting_u64(
                    &self.store,
                    &guild_text,
                    "management.workflows.max_reply_length",
                    1_000,
                )
                .clamp(1, 1_500) as usize,
                allow_mentions: setting_bool(
                    &self.store,
                    &guild_text,
                    "management.workflows.allow_mentions",
                    false,
                ),
            };
            for workflow in workflows {
                let decision = evaluate_workflow(
                    &policy,
                    &WorkflowObservation {
                        enabled: workflow.enabled,
                        trigger: workflow.trigger.clone(),
                        condition: workflow.condition.clone(),
                        action: workflow.action.clone(),
                        payload: workflow.payload.clone(),
                        message_content: message.content.clone(),
                        user_mention: format!("<@{}>", message.author.id),
                    },
                );
                if !decision.should_run {
                    continue;
                }
                let Ok(true) = self.store.record_workflow_run(
                    workflow.id,
                    &guild_text,
                    &message.id.to_string(),
                ) else {
                    continue;
                };
                if let Some(reply) = decision.reply {
                    let _ = message.channel_id.say(&ctx.http, reply).await;
                }
                if let Some(reaction) = decision.reaction {
                    let _ = message
                        .react(&ctx.http, ReactionType::Unicode(reaction))
                        .await;
                }
            }
        }
    }
}

fn helper_gateway_intents() -> GatewayIntents {
    GatewayIntents::GUILDS
        | GatewayIntents::GUILD_MEMBERS
        | GatewayIntents::GUILD_MODERATION
        | GatewayIntents::GUILD_MESSAGES
        | GatewayIntents::GUILD_MESSAGE_REACTIONS
        | GatewayIntents::GUILD_INVITES
        | GatewayIntents::GUILD_VOICE_STATES
        | GatewayIntents::GUILD_WEBHOOKS
        | GatewayIntents::AUTO_MODERATION_CONFIGURATION
        | GatewayIntents::AUTO_MODERATION_EXECUTION
        | GatewayIntents::MESSAGE_CONTENT
}

/// Growth activation measures a successful product action, not opening docs,
/// checking health, or completing onboarding.  Keeping this decision next to
/// the gateway handler prevents informational commands from inflating
/// `first_value` and daily-active guilds.
fn helper_command_counts_as_value(command: &str) -> bool {
    !matches!(
        command,
        "ping"
            | "language"
            | "help"
            | "setup"
            | "modules"
            | "status"
            | "dashboard"
            | "plan"
            | "privacy"
            | "permissions"
    )
}

fn helper_setup_is_complete(store: &Store, guild_id: &str) -> bool {
    store
        .get_setting(guild_id, "core.setup.completed")
        .ok()
        .flatten()
        .is_some_and(|value| value == "true")
}

pub async fn run(config: &Config) -> Result<()> {
    let intents = helper_gateway_intents();
    let store = Store::open(&config.database_url)?;
    let (topgg_trigger, topgg_guilds) = if let Some(token) = config.topgg_token.clone() {
        let (trigger, guilds) = spawn_topgg_metrics(
            config.discord_application_id.to_string(),
            token,
            store.clone(),
        );
        (Some(trigger), Some(guilds))
    } else {
        // No token is an intentional disabled state, but it must be visible in
        // the private tracker instead of silently looking healthy.
        let _ = store.record_topgg_sync_attempt(
            Utc::now().timestamp_millis(),
            None,
            None,
            false,
            TopggSyncDetail::Unconfigured,
        );
        (None, None)
    };
    let mut client = Client::builder(&config.discord_token, intents)
        .event_handler(Handler {
            store,
            spam: Arc::new(Mutex::new(HashMap::new())),
            duplicate_messages: Arc::new(Mutex::new(HashMap::new())),
            spam_action_at: Arc::new(Mutex::new(HashMap::new())),
            joins: Arc::new(Mutex::new(HashMap::new())),
            nuke_events: Arc::new(Mutex::new(HashMap::new())),
            xp_awarded_at: Arc::new(Mutex::new(HashMap::new())),
            scheduler_started: Arc::new(AtomicBool::new(false)),
            topgg_trigger,
            topgg_guilds,
            entitlements: EntitlementClient::new(
                config.entitlement_url.clone(),
                config.entitlement_secret.clone(),
            ),
            youtube: YouTubeClient::from_env(),
            rss: Some(RssClient::new()),
            twitch: TwitchClient::from_env(),
            bluesky: Some(BlueskyClient::new()),
            tiktok: TikTokClient::from_env(),
            tiktok_oauth: TikTokOAuthClient::from_env(),
            token_cipher: TokenCipher::new(&config.session_secret).ok(),
            instagram: InstagramClient::from_env(),
            kick: KickClient::from_env(),
            coingecko: Some(CoinGeckoClient::new()),
            gas: GasClient::new(),
        })
        .application_id(config.discord_application_id.into())
        .await?;
    client.start().await?;
    Ok(())
}

fn spawn_topgg_metrics(
    client_id: String,
    token: String,
    store: Store,
) -> (TopggMetricsTrigger, TopggGuilds) {
    let trigger = TopggMetricsTrigger::default();
    let guilds = TopggGuilds::default();
    let worker_trigger = trigger.clone();
    let worker_guilds = guilds.clone();
    tokio::spawn(async move {
        let Ok(http) = ReqwestTopggMetricsHttp::new() else {
            let _ = store.record_topgg_sync_attempt(
                Utc::now().timestamp_millis(),
                None,
                None,
                false,
                TopggSyncDetail::TransportFailure,
            );
            return;
        };
        // A zero during gateway connection would be a false public metric.
        while !worker_guilds.is_ready() {
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        let mut interval = tokio::time::interval(TOPGG_POST_INTERVAL);
        loop {
            tokio::select! {
                _ = interval.tick() => {},
                _ = worker_trigger.notified() => {},
            }
            let server_count = worker_guilds.count();
            let validation = validate_topgg_v1_token(&http, &token).await;
            let (outcome, sent_server_count) = if validation.succeeded() {
                (
                    post_topgg_stats_with_shards(&http, &client_id, &token, server_count, 1).await,
                    Some(server_count),
                )
            } else {
                (validation, None)
            };
            let _ = store.record_topgg_sync_attempt(
                Utc::now().timestamp_millis(),
                outcome.status(),
                sent_server_count,
                outcome.succeeded(),
                outcome.detail(),
            );
            if !outcome.succeeded() {
                warn!(
                    detail = outcome.detail().as_storage(),
                    status = ?outcome.status(),
                    server_count,
                    "helper Top.gg v1 validation or metrics publish failed"
                );
            }
        }
    });
    (trigger, guilds)
}

async fn run_youtube_worker(http: Arc<serenity::http::Http>, store: Store, youtube: YouTubeClient) {
    let mut interval = tokio::time::interval(Duration::from_secs(15));
    loop {
        interval.tick().await;
        let due = match store.due_youtube_subscriptions(Utc::now().timestamp_millis(), 25) {
            Ok(rows) => rows,
            Err(error) => {
                tracing::error!(%error, "youtube worker could not load subscriptions");
                continue;
            }
        };
        for subscription in due {
            if !feature_enabled(&store, &subscription.guild_id, "social.youtube", None) {
                let next = Utc::now().timestamp_millis() + subscription.interval_seconds * 1_000;
                let _ = store.update_youtube_poll(
                    subscription.id,
                    subscription.last_video_id.as_deref(),
                    next,
                    subscription.failure_count,
                    Some("feature_disabled"),
                );
                continue;
            }
            if let Err(error) =
                process_youtube_subscription(&http, &store, &youtube, &subscription).await
            {
                tracing::warn!(%error, subscription_id = subscription.id, "youtube subscription failed");
            }
        }
    }
}

async fn process_youtube_subscription(
    http: &serenity::http::Http,
    store: &Store,
    youtube: &YouTubeClient,
    subscription: &YouTubeSubscriptionRecord,
) -> Result<()> {
    let now = Utc::now().timestamp_millis();
    let interval_ms = subscription.interval_seconds.clamp(300, 86_400) * 1_000;
    let next = || now + interval_ms;
    let latest = match youtube.latest_video(&subscription.source_channel_id).await {
        Ok(video) => video,
        Err(error) => {
            let failures = subscription.failure_count.saturating_add(1).min(8);
            let backoff = (subscription.interval_seconds * (1_i64 << failures.min(4))).min(3_600);
            store.update_youtube_poll(
                subscription.id,
                subscription.last_video_id.as_deref(),
                now + backoff * 1_000,
                failures,
                Some(&provider_error_code(&error)),
            )?;
            return Err(error);
        }
    };
    let Some(video) = latest else {
        store.update_youtube_poll(
            subscription.id,
            subscription.last_video_id.as_deref(),
            next(),
            0,
            None,
        )?;
        return Ok(());
    };
    if subscription.last_video_id.is_none() {
        // Establish a baseline on first poll. Existing videos must not flood
        // a server when an administrator enables an alert.
        store.update_youtube_poll(subscription.id, Some(&video.id), next(), 0, None)?;
        return Ok(());
    }
    if subscription.last_video_id.as_deref() == Some(video.id.as_str()) {
        store.update_youtube_poll(subscription.id, Some(&video.id), next(), 0, None)?;
        return Ok(());
    }
    let content = format_youtube_message(
        &subscription.message_template,
        &subscription.mention,
        &video,
        &subscription.source_channel_id,
    );
    let channel_id = subscription
        .target_channel_id
        .parse::<u64>()
        .map_err(|_| anyhow::anyhow!("invalid_discord_channel_id"))?;
    ChannelId::new(channel_id).say(http, content).await?;
    store.update_youtube_poll(subscription.id, Some(&video.id), next(), 0, None)?;
    Ok(())
}

fn provider_error_code(error: &anyhow::Error) -> String {
    let value = error.to_string();
    if value.starts_with("youtube_api_error:") || value.starts_with("rss_http_error:") {
        value
    } else {
        "provider_request_failed".into()
    }
}

fn rss_retry_seconds(interval_seconds: i64, failure_count: i64) -> i64 {
    let base = interval_seconds.clamp(300, 86_400);
    let multiplier = 1_i64 << failure_count.clamp(0, 4);
    base.saturating_mul(multiplier).min(3_600)
}

async fn run_rss_worker(http: Arc<serenity::http::Http>, store: Store, rss: RssClient) {
    let mut interval = tokio::time::interval(Duration::from_secs(15));
    loop {
        interval.tick().await;
        let due = match store.due_rss_subscriptions(Utc::now().timestamp_millis(), 25) {
            Ok(rows) => rows,
            Err(error) => {
                tracing::error!(%error, "rss worker could not load subscriptions");
                continue;
            }
        };
        for subscription in due {
            // Podcast alerts are the same bounded RSS/Atom transport. A
            // subscription is active when either product surface is enabled;
            // this keeps the worker single-purpose and prevents duplicate
            // polling or delivery.
            let rss_enabled = feature_enabled(&store, &subscription.guild_id, "social.rss", None);
            let podcasts_enabled =
                feature_enabled(&store, &subscription.guild_id, "social.podcasts", None);
            if !rss_enabled && !podcasts_enabled {
                let next = Utc::now().timestamp_millis() + subscription.interval_seconds * 1_000;
                let _ = store.update_rss_poll(
                    subscription.id,
                    subscription.last_item_id.as_deref(),
                    next,
                    subscription.failure_count,
                    Some("feature_disabled"),
                );
                continue;
            }
            if let Err(error) = process_rss_subscription(&http, &store, &rss, &subscription).await {
                tracing::warn!(%error, subscription_id = subscription.id, "rss subscription failed");
            }
        }
    }
}

async fn process_rss_subscription(
    http: &serenity::http::Http,
    store: &Store,
    rss: &RssClient,
    subscription: &RssSubscriptionRecord,
) -> Result<()> {
    let now = Utc::now().timestamp_millis();
    let interval_ms = subscription.interval_seconds.clamp(300, 86_400) * 1_000;
    let next = || now + interval_ms;
    let feed = match rss.fetch(&subscription.feed_url).await {
        Ok(feed) => feed,
        Err(error) => {
            let failures = subscription.failure_count.saturating_add(1).min(8);
            let backoff = rss_retry_seconds(subscription.interval_seconds, failures);
            store.update_rss_poll(
                subscription.id,
                subscription.last_item_id.as_deref(),
                now + backoff * 1_000,
                failures,
                Some(&provider_error_code(&error)),
            )?;
            return Err(error);
        }
    };
    let Some(item) = feed.and_then(|value| value.latest) else {
        store.update_rss_poll(
            subscription.id,
            subscription.last_item_id.as_deref(),
            next(),
            0,
            None,
        )?;
        return Ok(());
    };
    if subscription.last_item_id.is_none() {
        store.update_rss_poll(subscription.id, Some(&item.id), next(), 0, None)?;
        return Ok(());
    }
    if subscription.last_item_id.as_deref() == Some(item.id.as_str()) {
        store.update_rss_poll(subscription.id, Some(&item.id), next(), 0, None)?;
        return Ok(());
    }
    let content = format_rss_message(&subscription.message_template, &subscription.mention, &item);
    let channel_id = subscription
        .target_channel_id
        .parse::<u64>()
        .map_err(|_| anyhow::anyhow!("invalid_discord_channel_id"))?;
    if let Err(error) = ChannelId::new(channel_id).say(http, content).await {
        let failures = subscription.failure_count.saturating_add(1).min(8);
        let backoff = rss_retry_seconds(subscription.interval_seconds, failures);
        // Do not advance last_item_id until Discord confirms delivery.  The
        // bounded retry keeps a transient 429/5xx from hot-looping every
        // worker tick while still allowing the item to be delivered later.
        store.update_rss_poll(
            subscription.id,
            subscription.last_item_id.as_deref(),
            now + backoff * 1_000,
            failures,
            Some("discord_delivery_failed"),
        )?;
        return Err(error.into());
    }
    store.update_rss_poll(subscription.id, Some(&item.id), next(), 0, None)?;
    Ok(())
}

async fn run_bluesky_worker(http: Arc<serenity::http::Http>, store: Store, bluesky: BlueskyClient) {
    let mut interval = tokio::time::interval(Duration::from_secs(15));
    loop {
        interval.tick().await;
        let due = match store.due_bluesky_subscriptions(Utc::now().timestamp_millis(), 25) {
            Ok(rows) => rows,
            Err(error) => {
                tracing::error!(%error, "bluesky worker could not load subscriptions");
                continue;
            }
        };
        for subscription in due {
            if !feature_enabled(&store, &subscription.guild_id, "social.bluesky", None) {
                let next = Utc::now().timestamp_millis() + subscription.interval_seconds * 1_000;
                let _ = store.update_bluesky_poll(
                    subscription.id,
                    subscription.last_post_uri.as_deref(),
                    next,
                    subscription.failure_count,
                    Some("feature_disabled"),
                );
                continue;
            }
            if let Err(error) =
                process_bluesky_subscription(&http, &store, &bluesky, &subscription).await
            {
                tracing::warn!(%error, subscription_id = subscription.id, "bluesky notification failed");
            }
        }
    }
}

fn format_crypto_quotes(quotes: &[CoinGeckoQuote]) -> String {
    let rows = quotes.iter().take(20).map(|quote| {
        let change = quote
            .change_24h
            .map(|value| format!(" ({value:+.2}% 24h)"))
            .unwrap_or_default();
        format!(
            "**{}**: {:.8} {}{}",
            quote.id,
            quote.price,
            quote.currency.to_ascii_uppercase(),
            change
        )
    });
    let mut content = rows.collect::<Vec<_>>().join("\n");
    content.push_str("\n\nSource: CoinGecko. Read-only market data, not financial advice.");
    content.chars().take(2_000).collect()
}

fn format_gas_quote(quote: &GasQuote) -> String {
    let block = quote
        .block_number
        .map(|value| format!("Block {value}."))
        .unwrap_or_default();
    format!(
        "**{}** gas price: {:.3} Gwei. {block}\n\nSource: operator-approved RPC; read-only network data.",
        quote.network, quote.gas_price_gwei,
    )
}

async fn run_gas_tracker_worker(http: Arc<serenity::http::Http>, store: Store, gas: GasClient) {
    let mut interval = tokio::time::interval(Duration::from_secs(60));
    loop {
        interval.tick().await;
        let rows = match store.enabled_feature_settings("web3.gas_tracker") {
            Ok(rows) => rows,
            Err(error) => {
                tracing::error!(%error, "gas tracker worker could not load settings");
                continue;
            }
        };
        let now = Utc::now().timestamp_millis();
        for setting in rows {
            if !feature_enabled(&store, &setting.guild_id, "web3.gas_tracker", None) {
                continue;
            }
            let config =
                serde_json::from_str::<serde_json::Value>(&setting.config_json).unwrap_or_default();
            let Some(object) = config.as_object() else {
                continue;
            };
            // Published projections are the live source; the JSON fallback
            // keeps releases before the adapter registry readable.
            let interval_seconds = setting_i64(
                &store,
                &setting.guild_id,
                "web3.gas_tracker.interval_seconds",
                object
                    .get("intervalSeconds")
                    .and_then(serde_json::Value::as_i64)
                    .unwrap_or(900),
            )
            .clamp(300, 86_400);
            let last_poll = setting_i64(
                &store,
                &setting.guild_id,
                "web3_gas_tracker.last_poll_at",
                0,
            );
            if last_poll > 0 && now.saturating_sub(last_poll) < interval_seconds * 1_000 {
                continue;
            }
            let Some(channel_id) = setting_string(
                &store,
                &setting.guild_id,
                "web3.gas_tracker.target_channel_id",
            )
            .or_else(|| {
                object
                    .get("targetChannelId")
                    .and_then(serde_json::Value::as_str)
                    .map(ToOwned::to_owned)
            })
            .and_then(|value| value.parse::<u64>().ok()) else {
                continue;
            };
            let network = setting_string(&store, &setting.guild_id, "web3.gas_tracker.network")
                .or_else(|| {
                    object
                        .get("network")
                        .and_then(serde_json::Value::as_str)
                        .map(ToOwned::to_owned)
                })
                .unwrap_or_else(|| "ethereum".into());
            let quote = match gas.quote(&network).await {
                Ok(quote) => quote,
                Err(error) => {
                    tracing::warn!(%error, guild_id = %setting.guild_id, network, "gas tracker provider request failed");
                    continue;
                }
            };
            let template = setting_string(
                &store,
                &setting.guild_id,
                "web3.gas_tracker.message_template",
            )
            .or_else(|| {
                object
                    .get("messageTemplate")
                    .and_then(serde_json::Value::as_str)
                    .map(ToOwned::to_owned)
            })
            .unwrap_or_else(|| "{network} gas: {gasPriceGwei} Gwei (block {blockNumber})".into());
            let content = template
                .replace("{network}", &quote.network)
                .replace("{gasPriceGwei}", &format!("{:.3}", quote.gas_price_gwei))
                .replace(
                    "{blockNumber}",
                    &quote
                        .block_number
                        .map(|value| value.to_string())
                        .unwrap_or_else(|| "unknown".into()),
                )
                .chars()
                .take(2_000)
                .collect::<String>();
            if ChannelId::new(channel_id)
                .say(&http, content)
                .await
                .is_err()
            {
                tracing::warn!(guild_id = %setting.guild_id, "gas tracker Discord delivery failed");
                continue;
            }
            let _ = store.set_setting(
                &setting.guild_id,
                "web3_gas_tracker.last_poll_at",
                &now.to_string(),
            );
        }
    }
}

async fn run_crypto_stats_worker(
    http: Arc<serenity::http::Http>,
    store: Store,
    coingecko: CoinGeckoClient,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(60));
    loop {
        interval.tick().await;
        let rows = match store.enabled_feature_settings("web3.crypto_stats") {
            Ok(rows) => rows,
            Err(error) => {
                tracing::error!(%error, "crypto stats worker could not load settings");
                continue;
            }
        };
        let now = Utc::now().timestamp_millis();
        for setting in rows {
            if !feature_enabled(&store, &setting.guild_id, "web3.crypto_stats", None) {
                continue;
            }
            let config =
                serde_json::from_str::<serde_json::Value>(&setting.config_json).unwrap_or_default();
            let Some(object) = config.as_object() else {
                continue;
            };
            let interval_seconds = setting_i64(
                &store,
                &setting.guild_id,
                "web3_crypto_stats.interval_seconds",
                object
                    .get("intervalSeconds")
                    .and_then(serde_json::Value::as_i64)
                    .unwrap_or(900),
            )
            .clamp(300, 86_400);
            let last_poll = setting_i64(
                &store,
                &setting.guild_id,
                "web3_crypto_stats.last_poll_at",
                0,
            );
            if last_poll > 0 && now.saturating_sub(last_poll) < interval_seconds * 1_000 {
                continue;
            }
            let ids = setting_string(&store, &setting.guild_id, "web3_crypto_stats.coin_ids")
                .or_else(|| {
                    object
                        .get("coinIds")
                        .and_then(serde_json::Value::as_str)
                        .map(ToOwned::to_owned)
                })
                .unwrap_or_else(|| "bitcoin".into())
                .split(',')
                .map(str::trim)
                .filter(|id| !id.is_empty())
                .take(20)
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>();
            let currency = setting_string(&store, &setting.guild_id, "web3_crypto_stats.currency")
                .or_else(|| {
                    object
                        .get("currency")
                        .and_then(serde_json::Value::as_str)
                        .map(ToOwned::to_owned)
                })
                .unwrap_or_else(|| "usd".into());
            let Some(channel_id) = setting_string(
                &store,
                &setting.guild_id,
                "web3_crypto_stats.target_channel_id",
            )
            .or_else(|| {
                object
                    .get("targetChannelId")
                    .and_then(serde_json::Value::as_str)
                    .map(ToOwned::to_owned)
            })
            .and_then(|value| value.parse::<u64>().ok()) else {
                continue;
            };
            let quotes = match coingecko.quotes(&ids, &currency).await {
                Ok(quotes) => quotes,
                Err(error) => {
                    tracing::warn!(%error, guild_id = %setting.guild_id, "crypto stats provider request failed");
                    continue;
                }
            };
            if quotes.is_empty() {
                let _ = store.set_setting(
                    &setting.guild_id,
                    "web3_crypto_stats.last_poll_at",
                    &now.to_string(),
                );
                continue;
            }
            let template = setting_string(
                &store,
                &setting.guild_id,
                "web3_crypto_stats.message_template",
            )
            .or_else(|| {
                object
                    .get("messageTemplate")
                    .and_then(serde_json::Value::as_str)
                    .map(ToOwned::to_owned)
            })
            .unwrap_or_else(|| "Crypto update: {coins}".into());
            let content = template
                .replace("{coins}", &format_crypto_quotes(&quotes))
                .replace("{currency}", &currency.to_ascii_uppercase())
                .chars()
                .take(2_000)
                .collect::<String>();
            let channel = ChannelId::new(channel_id);
            let message_key = "web3_crypto_stats.message_id";
            let existing = setting_string(&store, &setting.guild_id, message_key)
                .and_then(|value| value.parse::<u64>().ok());
            let delivered = if let Some(message_id) = existing {
                channel
                    .edit_message(
                        &http,
                        MessageId::new(message_id),
                        EditMessage::new().content(content.clone()),
                    )
                    .await
                    .is_ok()
            } else {
                false
            };
            if !delivered {
                match channel.say(&http, content).await {
                    Ok(message) => {
                        let _ = store.set_setting(
                            &setting.guild_id,
                            message_key,
                            &message.id.to_string(),
                        );
                    }
                    Err(error) => {
                        tracing::warn!(%error, guild_id = %setting.guild_id, "crypto stats Discord delivery failed");
                        continue;
                    }
                }
            }
            let _ = store.set_setting(
                &setting.guild_id,
                "web3_crypto_stats.last_poll_at",
                &now.to_string(),
            );
        }
    }
}

/// Ensure temporary anti-raid containment always restores the server's prior
/// join-gate state, including after a gateway reconnect when no member joins.
async fn run_anti_raid_expiry_worker(store: Store) {
    let mut interval = tokio::time::interval(Duration::from_secs(15));
    loop {
        interval.tick().await;
        let guilds = match store.active_anti_raid_latch_guilds(1_000) {
            Ok(guilds) => guilds,
            Err(error) => {
                warn!(%error, "anti-raid expiry worker could not load active latches");
                continue;
            }
        };
        let now = Utc::now().timestamp();
        for guild_id in guilds {
            match store.release_expired_anti_raid_latch(&guild_id, now) {
                Ok(true) => {
                    info!(%guild_id, "anti-raid containment expired and restored the prior join gate");
                }
                Ok(false) => {}
                Err(error) => {
                    warn!(%guild_id, %error, "anti-raid expiry worker could not release containment");
                }
            }
        }
    }
}

/// Purge only lifecycle rows whose confirmed departure is older than the
/// documented 30-day retention period. Running once immediately and then
/// daily keeps the data boundary correct even when the bot is long-lived.
async fn run_growth_lifecycle_purge_worker(store: Store) {
    loop {
        match store.purge_growth_lifecycle(Utc::now().timestamp_millis()) {
            Ok(purged) if purged > 0 => {
                info!(purged, "purged expired Helper growth lifecycle rows");
            }
            Ok(_) => {}
            Err(error) => {
                warn!(%error, "could not purge expired Helper growth lifecycle rows");
            }
        }
        tokio::time::sleep(Duration::from_secs(24 * 60 * 60)).await;
    }
}

/// Keep the configured Helper nickname synchronized with the live Discord
/// member state, including removal after a feature is disabled.
async fn run_nickname_worker(http: Arc<serenity::http::Http>, store: Store) {
    let mut interval = tokio::time::interval(Duration::from_secs(30));
    loop {
        interval.tick().await;
        let user = match http.get_current_user().await {
            Ok(user) => user,
            Err(error) => {
                tracing::warn!(%error, "nickname worker could not resolve the Helper user");
                continue;
            }
        };
        let rows = match store.feature_settings("management.nickname") {
            Ok(rows) => rows,
            Err(error) => {
                tracing::warn!(%error, "nickname worker could not load settings");
                continue;
            }
        };
        for setting in rows {
            let Ok(config) = serde_json::from_str::<serde_json::Value>(&setting.config_json) else {
                continue;
            };
            // A disabled setting is still loaded so the worker can remove a
            // nickname that was applied by an earlier revision.  This makes
            // the panel's off switch a real, reversible Discord operation.
            let nickname = if setting.enabled {
                config
                    .get("nickname")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default()
                    .trim()
            } else {
                ""
            };
            let nickname_config = serde_json::json!({"nickname": nickname});
            let nickname_decision = evaluate_nickname(&nickname_config);
            if !nickname_decision.allowed {
                continue;
            }
            let nickname = nickname_decision.nickname.as_str();
            let Ok(guild_id) = setting.guild_id.parse::<u64>() else {
                continue;
            };
            let guild_id = serenity::all::GuildId::new(guild_id);
            let Ok(member) = guild_id.member(&http, user.id).await else {
                continue;
            };
            if member.nick.as_deref().unwrap_or_default() == nickname {
                continue;
            }
            if let Err(error) = guild_id
                .edit_member(
                    &http,
                    user.id,
                    serenity::all::EditMember::new().nickname(nickname.to_owned()),
                )
                .await
            {
                tracing::warn!(guild_id = %guild_id, %error, "failed to apply configured Helper nickname");
            }
        }
    }
}

async fn run_stats_channel_worker(http: Arc<serenity::http::Http>, store: Store) {
    let mut interval = tokio::time::interval(Duration::from_secs(60));
    loop {
        interval.tick().await;
        let rows = match store.enabled_feature_settings("insights.stats") {
            Ok(rows) => rows,
            Err(error) => {
                tracing::error!(%error, "stats worker could not load settings");
                continue;
            }
        };
        let now = Utc::now().timestamp_millis();
        for setting in rows {
            if !feature_enabled(&store, &setting.guild_id, "insights.stats", None) {
                continue;
            }
            let config =
                serde_json::from_str::<serde_json::Value>(&setting.config_json).unwrap_or_default();
            let Some(object) = config.as_object() else {
                continue;
            };
            // Prefer the atomically published projection. The JSON fallback
            // keeps older revisions readable during the migration window, but
            // never lets a stale config blob override a newer projection.
            let channel_id = setting_string(&store, &setting.guild_id, "insights.stats.channel_id")
                .or_else(|| {
                    object
                        .get("channelId")
                        .and_then(serde_json::Value::as_str)
                        .map(ToOwned::to_owned)
                })
                .filter(|value| !value.trim().is_empty())
                .and_then(|value| value.parse::<u64>().ok());
            let Some(channel_id) = channel_id else {
                continue;
            };
            let template =
                setting_string(&store, &setting.guild_id, "insights.stats.name_template")
                    .or_else(|| {
                        object
                            .get("nameTemplate")
                            .and_then(serde_json::Value::as_str)
                            .map(ToOwned::to_owned)
                    })
                    .unwrap_or_else(|| "messages-{messages}".to_owned());
            let needs_members = helper_core::member_counter::uses_member_count(&template);
            let refresh_minutes = setting_i64(
                &store,
                &setting.guild_id,
                "insights.stats.interval_minutes",
                object
                    .get("intervalMinutes")
                    .and_then(serde_json::Value::as_i64)
                    .unwrap_or(15),
            );
            let refresh_minutes = helper_core::member_counter::refresh_interval_minutes(
                refresh_minutes,
                needs_members,
            );
            let last_refresh = setting_i64(
                &store,
                &setting.guild_id,
                "insights.stats.last_channel_refresh_at",
                0,
            );
            if last_refresh > 0
                && now.saturating_sub(last_refresh) < refresh_minutes.saturating_mul(60_000)
            {
                continue;
            }
            let channel = match serenity::all::ChannelId::new(channel_id)
                .to_channel(&http)
                .await
            {
                Ok(channel) => channel.guild(),
                Err(error) => {
                    tracing::warn!(%error, guild_id = %setting.guild_id, channel_id, "stats counter channel lookup failed");
                    continue;
                }
            };
            let Some(channel) =
                channel.filter(|channel| channel.guild_id.to_string() == setting.guild_id)
            else {
                tracing::warn!(guild_id = %setting.guild_id, channel_id, "stats counter refused a channel outside its guild");
                continue;
            };
            let members = if needs_members {
                match channel.guild_id.to_partial_guild_with_counts(&http).await {
                    Ok(guild) => guild.approximate_member_count,
                    Err(error) => {
                        tracing::warn!(%error, guild_id = %setting.guild_id, "stats member count lookup failed; keeping current name");
                        continue;
                    }
                }
            } else {
                None
            };
            let window_days = setting_i64(
                &store,
                &setting.guild_id,
                "insights.stats.window_days",
                object
                    .get("windowDays")
                    .and_then(serde_json::Value::as_i64)
                    .unwrap_or(7),
            )
            .clamp(1, 30) as u32;
            let stats = match store.stats_for(&setting.guild_id, window_days) {
                Ok(stats) => stats,
                Err(error) => {
                    tracing::warn!(%error, guild_id = %setting.guild_id, "stats snapshot query failed");
                    continue;
                }
            };
            let messages: i64 = stats.iter().map(|(_, messages, _, _)| messages).sum();
            let joins: i64 = stats.iter().map(|(_, _, joins, _)| joins).sum();
            let leaves: i64 = stats.iter().map(|(_, _, _, leaves)| leaves).sum();
            let stats_config = serde_json::json!({
                "windowDays": window_days,
                "channelId": channel_id.to_string(),
                "nameTemplate": template,
            });
            let decision = evaluate_stats_with_members(
                &stats_config,
                Some(&channel_id.to_string()),
                messages,
                joins,
                leaves,
                members,
            );
            if !decision.allowed {
                continue;
            }
            if !feature_enabled(&store, &setting.guild_id, "insights.stats", None) {
                continue;
            }
            if channel.name != decision.name
                && let Err(error) = serenity::all::ChannelId::new(channel_id)
                    .edit(
                        &http,
                        serenity::all::EditChannel::new().name(&decision.name),
                    )
                    .await
            {
                tracing::warn!(%error, guild_id = %setting.guild_id, channel_id, "stats channel update failed");
                continue;
            }
            tracing::info!(guild_id = %setting.guild_id, channel_id, members, changed = channel.name != decision.name, "stats counter refreshed");
            let _ = store.set_setting(
                &setting.guild_id,
                "insights.stats.last_channel_refresh_at",
                &now.to_string(),
            );
        }
    }
}

async fn process_bluesky_subscription(
    http: &serenity::http::Http,
    store: &Store,
    bluesky: &BlueskyClient,
    subscription: &BlueskySubscriptionRecord,
) -> Result<()> {
    let now = Utc::now().timestamp_millis();
    let interval_ms = subscription.interval_seconds.clamp(300, 86_400) * 1_000;
    let next = || now + interval_ms;
    let latest = match bluesky.latest_post(&subscription.source_handle).await {
        Ok(post) => post,
        Err(error) => {
            let failures = subscription.failure_count.saturating_add(1).min(8);
            let backoff = (subscription.interval_seconds * (1_i64 << failures.min(4))).min(3_600);
            store.update_bluesky_poll(
                subscription.id,
                subscription.last_post_uri.as_deref(),
                now + backoff * 1_000,
                failures,
                Some("bluesky_provider_failed"),
            )?;
            return Err(error);
        }
    };
    let Some(post) = latest else {
        store.update_bluesky_poll(
            subscription.id,
            subscription.last_post_uri.as_deref(),
            next(),
            0,
            None,
        )?;
        return Ok(());
    };
    if subscription.last_post_uri.is_none() {
        // Establish a baseline on first poll to avoid a burst of historical
        // posts when a profile alert is enabled.
        store.update_bluesky_poll(subscription.id, Some(&post.uri), next(), 0, None)?;
        return Ok(());
    }
    if subscription.last_post_uri.as_deref() == Some(post.uri.as_str()) {
        store.update_bluesky_poll(subscription.id, Some(&post.uri), next(), 0, None)?;
        return Ok(());
    }
    let content =
        format_bluesky_message(&subscription.message_template, &subscription.mention, &post);
    let channel_id = subscription
        .target_channel_id
        .parse::<u64>()
        .map_err(|_| anyhow::anyhow!("invalid_discord_channel_id"))?;
    ChannelId::new(channel_id).say(http, content).await?;
    store.update_bluesky_poll(subscription.id, Some(&post.uri), next(), 0, None)?;
    Ok(())
}

fn format_bluesky_message(template: &str, mention: &str, post: &BlueskyPost) -> String {
    let rendered = template
        .replace("{handle}", &post.handle)
        .replace("{text}", &post.text)
        .replace("{url}", &post.url)
        .replace("{created_at}", &post.created_at)
        .replace("{uri}", &post.uri);
    let rendered = if mention.is_empty() {
        rendered
    } else {
        format!("{mention} {rendered}")
    };
    rendered.chars().take(2_000).collect()
}

async fn run_tiktok_worker(
    http: Arc<serenity::http::Http>,
    store: Store,
    fallback_tiktok: Option<TikTokClient>,
    oauth: Option<TikTokOAuthClient>,
    cipher: Option<TokenCipher>,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(30));
    loop {
        interval.tick().await;
        let approved =
            first_env_flag_is_true(&["TIKTOK_APP_APPROVED", "TIKTOK_DISPLAY_API_APPROVED"]);
        if !tiktok_runtime_allowed(
            approved,
            env_flag_is_true("TIKTOK_SANDBOX_MODE"),
            oauth.is_some() && cipher.is_some(),
            fallback_tiktok.is_some(),
        ) {
            continue;
        }
        let due = match store.due_tiktok_subscriptions(Utc::now().timestamp_millis(), 25) {
            Ok(rows) => rows,
            Err(error) => {
                tracing::error!(%error, "tiktok worker could not load subscriptions");
                continue;
            }
        };
        for subscription in due {
            if !feature_enabled(&store, &subscription.guild_id, "social.tiktok", None) {
                let next = Utc::now().timestamp_millis() + subscription.interval_seconds * 1_000;
                let _ = store.update_tiktok_poll(
                    subscription.id,
                    subscription.last_video_id.as_deref(),
                    next,
                    subscription.failure_count,
                    Some("feature_disabled"),
                );
                continue;
            }
            let client = match tiktok_client_for_guild(
                &store,
                &subscription.guild_id,
                oauth.as_ref(),
                cipher.as_ref(),
                fallback_tiktok.as_ref(),
                approved,
            )
            .await
            {
                Ok(client) => client,
                Err(error) => {
                    let next =
                        Utc::now().timestamp_millis() + subscription.interval_seconds * 1_000;
                    let _ = store.update_tiktok_poll(
                        subscription.id,
                        subscription.last_video_id.as_deref(),
                        next,
                        subscription.failure_count,
                        Some("tiktok_authorization_required"),
                    );
                    tracing::warn!(%error, subscription_id = subscription.id, "tiktok authorization unavailable");
                    continue;
                }
            };
            if let Err(error) =
                process_tiktok_subscription(&http, &store, &client, &subscription).await
            {
                tracing::warn!(%error, subscription_id = subscription.id, "tiktok notification failed");
            }
        }
    }
}

async fn tiktok_client_for_guild(
    store: &Store,
    guild_id: &str,
    oauth: Option<&TikTokOAuthClient>,
    cipher: Option<&TokenCipher>,
    fallback: Option<&TikTokClient>,
    allow_fallback: bool,
) -> Result<TikTokClient> {
    if let (Some(oauth), Some(cipher), Some(mut grant)) =
        (oauth, cipher, store.tiktok_grant(guild_id)?)
    {
        let now = Utc::now().timestamp();
        if grant.access_expires_at <= now + 300 {
            let refresh_token = cipher.open(&grant.refresh_token_sealed)?;
            let refreshed = oauth.refresh(&refresh_token).await?;
            grant.access_token_sealed = cipher.seal(&refreshed.access_token)?;
            grant.refresh_token_sealed = cipher.seal(&refreshed.refresh_token)?;
            grant.scopes = refreshed.scope;
            grant.access_expires_at = now.saturating_add(refreshed.expires_in);
            grant.refresh_expires_at = now.saturating_add(refreshed.refresh_expires_in);
            grant.updated_at = now;
            store.save_tiktok_grant(
                guild_id,
                &refreshed.open_id,
                &grant.display_name,
                &grant.access_token_sealed,
                &grant.refresh_token_sealed,
                &grant.scopes,
                grant.access_expires_at,
                grant.refresh_expires_at,
                grant.updated_at,
            )?;
        }
        let access_token = cipher.open(&grant.access_token_sealed)?;
        return TikTokClient::new(access_token, "https://open.tiktokapis.com")
            .ok_or_else(|| anyhow::anyhow!("tiktok_access_token_invalid"));
    }
    fallback
        .filter(|_| allow_fallback)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("tiktok_grant_missing"))
}

async fn process_tiktok_subscription(
    http: &serenity::http::Http,
    store: &Store,
    tiktok: &TikTokClient,
    subscription: &TikTokSubscriptionRecord,
) -> Result<()> {
    let now = Utc::now().timestamp_millis();
    let interval_ms = subscription.interval_seconds.clamp(900, 86_400) * 1_000;
    let next = || now + interval_ms;
    let videos = match tiktok.latest_videos().await {
        Ok(videos) => videos,
        Err(error) => {
            let failures = subscription.failure_count.saturating_add(1).min(8);
            let backoff = (subscription.interval_seconds * (1_i64 << failures.min(4))).min(3_600);
            store.update_tiktok_poll(
                subscription.id,
                subscription.last_video_id.as_deref(),
                now + backoff * 1_000,
                failures,
                Some("tiktok_provider_failed"),
            )?;
            return Err(error);
        }
    };
    let Some(video) = videos.into_iter().next() else {
        store.update_tiktok_poll(
            subscription.id,
            subscription.last_video_id.as_deref(),
            next(),
            0,
            None,
        )?;
        return Ok(());
    };
    if subscription.last_video_id.is_none()
        || subscription.last_video_id.as_deref() == Some(video.id.as_str())
    {
        store.update_tiktok_poll(subscription.id, Some(&video.id), next(), 0, None)?;
        return Ok(());
    }
    let content = format_tiktok_message(
        &subscription.message_template,
        &subscription.mention,
        &subscription.source_label,
        &video,
    );
    let channel_id = subscription
        .target_channel_id
        .parse::<u64>()
        .map_err(|_| anyhow::anyhow!("invalid_discord_channel_id"))?;
    ChannelId::new(channel_id).say(http, content).await?;
    store.update_tiktok_poll(subscription.id, Some(&video.id), next(), 0, None)?;
    Ok(())
}

fn format_tiktok_message(
    template: &str,
    mention: &str,
    label: &str,
    video: &TikTokVideo,
) -> String {
    let rendered = template
        .replace("{label}", label)
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
    rendered.chars().take(2_000).collect()
}

async fn run_instagram_worker(
    http: Arc<serenity::http::Http>,
    store: Store,
    instagram: InstagramClient,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(30));
    loop {
        interval.tick().await;
        if !instagram_runtime_allowed() {
            continue;
        }
        let due = match store.due_instagram_subscriptions(Utc::now().timestamp_millis(), 25) {
            Ok(rows) => rows,
            Err(error) => {
                tracing::error!(%error,"instagram worker could not load subscriptions");
                continue;
            }
        };
        for subscription in due {
            if !feature_enabled(&store, &subscription.guild_id, "social.instagram", None) {
                let next = Utc::now().timestamp_millis() + subscription.interval_seconds * 1000;
                let _ = store.update_instagram_poll(
                    subscription.id,
                    subscription.last_media_id.as_deref(),
                    next,
                    subscription.failure_count,
                    Some("feature_disabled"),
                );
                continue;
            }
            if let Err(error) =
                process_instagram_subscription(&http, &store, &instagram, &subscription).await
            {
                tracing::warn!(%error,subscription_id=subscription.id,"instagram notification failed");
            }
        }
    }
}

async fn process_instagram_subscription(
    http: &serenity::http::Http,
    store: &Store,
    instagram: &InstagramClient,
    subscription: &InstagramSubscriptionRecord,
) -> Result<()> {
    let now = Utc::now().timestamp_millis();
    let interval_ms = subscription.interval_seconds.clamp(900, 86400) * 1000;
    let next = || now + interval_ms;
    let media = match instagram.latest_media().await {
        Ok(media) => media,
        Err(error) => {
            let failures = subscription.failure_count.saturating_add(1).min(8);
            let backoff = (subscription.interval_seconds * (1_i64 << failures.min(4))).min(3600);
            store.update_instagram_poll(
                subscription.id,
                subscription.last_media_id.as_deref(),
                now + backoff * 1000,
                failures,
                Some("instagram_provider_failed"),
            )?;
            return Err(error);
        }
    };
    let Some(item) = media.into_iter().next() else {
        store.update_instagram_poll(
            subscription.id,
            subscription.last_media_id.as_deref(),
            next(),
            0,
            None,
        )?;
        return Ok(());
    };
    if subscription.last_media_id.is_none()
        || subscription.last_media_id.as_deref() == Some(item.id.as_str())
    {
        store.update_instagram_poll(subscription.id, Some(&item.id), next(), 0, None)?;
        return Ok(());
    }
    let content = format_instagram_message(
        &subscription.message_template,
        &subscription.mention,
        &subscription.source_label,
        &item,
    );
    let channel_id = subscription
        .target_channel_id
        .parse::<u64>()
        .map_err(|_| anyhow::anyhow!("invalid_discord_channel_id"))?;
    ChannelId::new(channel_id).say(http, content).await?;
    store.update_instagram_poll(subscription.id, Some(&item.id), next(), 0, None)?;
    Ok(())
}

fn format_instagram_message(
    template: &str,
    mention: &str,
    username: &str,
    media: &InstagramMedia,
) -> String {
    let rendered = template
        .replace("{username}", username)
        .replace("{label}", username)
        .replace("{caption}", &media.caption)
        .replace("{media_type}", &media.media_type)
        .replace("{url}", &media.permalink)
        .replace("{timestamp}", &media.timestamp)
        .replace("{id}", &media.id);
    let rendered = if mention.is_empty() {
        rendered
    } else {
        format!("{mention} {rendered}")
    };
    rendered.chars().take(2000).collect()
}

async fn run_kick_worker(http: Arc<serenity::http::Http>, store: Store, kick: KickClient) {
    let mut interval = tokio::time::interval(Duration::from_secs(30));
    loop {
        interval.tick().await;
        if !first_env_flag_is_true(&["KICK_APP_APPROVED", "KICK_API_APPROVED"]) {
            continue;
        }
        let due = match store.due_kick_subscriptions(Utc::now().timestamp_millis(), 25) {
            Ok(rows) => rows,
            Err(error) => {
                tracing::error!(%error,"kick worker could not load subscriptions");
                continue;
            }
        };
        for subscription in due {
            if !feature_enabled(&store, &subscription.guild_id, "social.kick", None) {
                let next = Utc::now().timestamp_millis() + subscription.interval_seconds * 1000;
                let _ = store.update_kick_poll(
                    subscription.id,
                    subscription.last_stream_id.as_deref(),
                    next,
                    subscription.failure_count,
                    Some("feature_disabled"),
                );
                continue;
            }
            if let Err(error) = process_kick_subscription(&http, &store, &kick, &subscription).await
            {
                tracing::warn!(%error,subscription_id=subscription.id,"kick notification failed");
            }
        }
    }
}

async fn process_kick_subscription(
    http: &serenity::http::Http,
    store: &Store,
    kick: &KickClient,
    subscription: &KickSubscriptionRecord,
) -> Result<()> {
    let now = Utc::now().timestamp_millis();
    let interval_ms = subscription.interval_seconds.clamp(300, 86400) * 1000;
    let next = || now + interval_ms;
    let stream = match kick.latest_stream(&subscription.source_handle).await {
        Ok(stream) => stream,
        Err(error) => {
            let failures = subscription.failure_count.saturating_add(1).min(8);
            let backoff = (subscription.interval_seconds * (1_i64 << failures.min(4))).min(3600);
            store.update_kick_poll(
                subscription.id,
                subscription.last_stream_id.as_deref(),
                now + backoff * 1000,
                failures,
                Some("kick_provider_failed"),
            )?;
            return Err(error);
        }
    };
    let Some(stream) = stream else {
        store.update_kick_poll(subscription.id, None, next(), 0, None)?;
        return Ok(());
    };
    if subscription.last_stream_id.is_none()
        || subscription.last_stream_id.as_deref() == Some(stream.id.as_str())
    {
        store.update_kick_poll(subscription.id, Some(&stream.id), next(), 0, None)?;
        return Ok(());
    }
    let content = format_kick_message(
        &subscription.message_template,
        &subscription.mention,
        &subscription.source_handle,
        &stream,
    );
    let channel_id = subscription
        .target_channel_id
        .parse::<u64>()
        .map_err(|_| anyhow::anyhow!("invalid_discord_channel_id"))?;
    ChannelId::new(channel_id).say(http, content).await?;
    store.update_kick_poll(subscription.id, Some(&stream.id), next(), 0, None)?;
    Ok(())
}

fn format_kick_message(template: &str, mention: &str, handle: &str, stream: &KickStream) -> String {
    let rendered = template
        .replace("{handle}", handle)
        .replace("{title}", &stream.title)
        .replace("{category}", &stream.category)
        .replace("{url}", &stream.url)
        .replace("{started_at}", &stream.started_at)
        .replace("{id}", &stream.id);
    let rendered = if mention.is_empty() {
        rendered
    } else {
        format!("{mention} {rendered}")
    };
    rendered.chars().take(2000).collect()
}

async fn run_twitch_worker(http: Arc<serenity::http::Http>, store: Store) {
    let mut interval = tokio::time::interval(Duration::from_secs(5));
    loop {
        interval.tick().await;
        let due = match store.due_twitch_subscriptions(Utc::now().timestamp_millis(), 25) {
            Ok(rows) => rows,
            Err(error) => {
                tracing::error!(%error, "twitch worker could not load subscriptions");
                continue;
            }
        };
        for subscription in due {
            if !feature_enabled(&store, &subscription.guild_id, "social.twitch", None) {
                if let Some(event_id) = subscription.pending_event_id.as_deref() {
                    let _ = store.ack_twitch_event(
                        subscription.id,
                        event_id,
                        i64::MAX,
                        subscription.failure_count,
                        Some("feature_disabled"),
                    );
                }
                continue;
            }
            if let Err(error) = process_twitch_subscription(&http, &store, &subscription).await {
                tracing::warn!(%error, subscription_id = subscription.id, "twitch notification failed");
            }
        }
    }
}

async fn process_twitch_subscription(
    http: &serenity::http::Http,
    store: &Store,
    subscription: &TwitchSubscriptionRecord,
) -> Result<()> {
    let Some(event_id) = subscription.pending_event_id.as_deref() else {
        return Ok(());
    };
    let content = format_twitch_message(
        &subscription.message_template,
        &subscription.mention,
        &subscription.source_login,
        subscription
            .pending_stream_id
            .as_deref()
            .unwrap_or_default(),
        subscription
            .pending_started_at
            .as_deref()
            .unwrap_or_default(),
    );
    let channel_id = subscription
        .target_channel_id
        .parse::<u64>()
        .map_err(|_| anyhow::anyhow!("invalid_discord_channel_id"))?;
    if let Err(error) = ChannelId::new(channel_id).say(http, content).await {
        let failures = subscription.failure_count.saturating_add(1).min(8);
        let backoff = 5_i64 * (1_i64 << failures.min(6));
        store.retry_twitch_event(
            subscription.id,
            event_id,
            Utc::now().timestamp_millis() + backoff * 1_000,
            failures,
            Some("discord_delivery_failed"),
        )?;
        return Err(error.into());
    }
    store.ack_twitch_event(subscription.id, event_id, i64::MAX, 0, None)?;
    Ok(())
}

fn configured_achievement_milestones(
    store: &Store,
    guild_id: &str,
) -> [(&'static str, &'static str, i64); 3] {
    [
        (
            "first_steps",
            "First steps",
            setting_u64(
                store,
                guild_id,
                "community.achievements.first_threshold",
                100,
            ) as i64,
        ),
        (
            "regular",
            "Regular",
            setting_u64(
                store,
                guild_id,
                "community.achievements.regular_threshold",
                1_000,
            ) as i64,
        ),
        (
            "community_pillar",
            "Community pillar",
            setting_u64(
                store,
                guild_id,
                "community.achievements.pillar_threshold",
                10_000,
            ) as i64,
        ),
    ]
}

fn achievement_policy_for_store(store: &Store, guild_id: &str) -> AchievementPolicy {
    let milestones = configured_achievement_milestones(store, guild_id);
    AchievementPolicy {
        first_threshold: milestones[0].2,
        regular_threshold: milestones[1].2,
        pillar_threshold: milestones[2].2,
    }
}

fn achievement_reward_role_for_store(
    store: &Store,
    guild_id: &str,
    achievement_key: &str,
) -> Option<u64> {
    let setting_key = match achievement_key {
        "first_steps" => "community.achievements.first_reward_role",
        "regular" => "community.achievements.regular_reward_role",
        "community_pillar" => "community.achievements.pillar_reward_role",
        _ => return None,
    };
    setting_string(store, guild_id, setting_key).and_then(|value| value.parse::<u64>().ok())
}

impl Handler {
    /// Reconcile an existing starboard entry after the source message changes.
    /// Reaction events are not emitted for edits, so without this pass the
    /// board would keep stale text/attachments until the next reaction.
    async fn reconcile_starboard_entry(
        &self,
        ctx: &Context,
        guild_id: serenity::all::GuildId,
        channel_id: ChannelId,
        message_id: serenity::all::MessageId,
        message: Option<&serenity::all::Message>,
    ) {
        let guild_text = guild_id.to_string();
        if !feature_enabled(
            &self.store,
            &guild_text,
            "community.starboard",
            Some("feature.community.starboard"),
        ) {
            return;
        }
        let Ok(Some(entry)) = self.store.star_entry(&guild_text, &message_id.to_string()) else {
            return;
        };
        let Some(board_id) =
            setting_string(&self.store, &guild_text, "community.starboard.channel_id")
                .and_then(|value| value.parse::<u64>().ok())
        else {
            return;
        };
        if board_id == channel_id.get() {
            return;
        }
        let original = if let Some(message) = message {
            message.clone()
        } else {
            match channel_id.message(&ctx.http, message_id).await {
                Ok(message) => message,
                Err(_) => return,
            }
        };
        let configured_emoji =
            setting_string(&self.store, &guild_text, "community.starboard.emoji")
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| "⭐".to_string());
        let reaction_emoji = if configured_emoji == "⭐"
            && !original.reactions.iter().any(|item| {
                item.reaction_type == serenity::all::ReactionType::Unicode(configured_emoji.clone())
                    && item.count_details.normal > 0
            }) {
            "🌟"
        } else {
            configured_emoji.as_str()
        };
        let reaction_type = serenity::all::ReactionType::Unicode(reaction_emoji.to_string());
        let Ok(users) = channel_id
            .reaction_users(
                &ctx.http,
                message_id,
                reaction_type.clone(),
                Some(100),
                None,
            )
            .await
        else {
            return;
        };
        let author_role_ids = guild_id
            .member(&ctx.http, original.author.id)
            .await
            .map(|member| {
                member
                    .roles
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let policy = starboard_policy_for_store(&self.store, &guild_text);
        let mut decision = evaluate_starboard(
            &policy,
            &StarboardObservation {
                source_channel_id: channel_id.to_string(),
                author_id: original.author.id.to_string(),
                reactor_ids: users.iter().map(|user| user.id.to_string()).collect(),
                author_role_ids,
                has_attachments: !original.attachments.is_empty(),
            },
        );
        if !decision.ignored {
            let normal_reactions = original
                .reactions
                .iter()
                .find(|item| item.reaction_type == reaction_type)
                .map(|item| item.count_details.normal)
                .unwrap_or(users.len() as u64);
            decision.count = decision.count.max(starboard_reaction_count(
                normal_reactions,
                users.iter().any(|user| user.id == original.author.id),
                policy.allow_self_star,
            ));
            decision.should_publish = decision.count >= decision.threshold;
        }
        let board = ChannelId::new(board_id);
        if !decision.should_publish {
            if let Ok(starboard_message_id) = entry.starboard_message_id.parse::<u64>() {
                let _ = board
                    .delete_message(&ctx.http, MessageId::new(starboard_message_id))
                    .await;
            }
            let _ = self
                .store
                .delete_star_entry(&guild_text, &message_id.to_string());
            return;
        }
        let count = decision.count as i64;
        let link = format!(
            "https://discord.com/channels/{}/{}/{}",
            guild_id, channel_id, message_id
        );
        let content =
            starboard_message_content(&policy, &configured_emoji, count, &original, &link);
        if let Ok(starboard_message_id) = entry.starboard_message_id.parse::<u64>()
            && starboard_display::publish(
                ctx,
                board,
                Some(MessageId::new(starboard_message_id)),
                &original,
                count,
                &link,
                &content,
            )
            .await
            .is_ok()
        {
            let _ = self.store.upsert_star_entry(
                &guild_text,
                &message_id.to_string(),
                &entry.starboard_message_id,
                count,
            );
        }
    }

    /// Persist milestone unlocks before announcing them.  This keeps the
    /// message and voice XP paths idempotent across gateway retries and makes
    /// `/achievements` a real history instead of a recalculated display.
    async fn announce_achievement_unlocks(
        &self,
        ctx: &Context,
        guild_id: serenity::all::GuildId,
        user_id: &str,
        xp: i64,
        source_channel: Option<ChannelId>,
    ) {
        if !feature_enabled(
            &self.store,
            &guild_id.to_string(),
            "community.achievements",
            None,
        ) {
            return;
        }
        let guild_text = guild_id.to_string();
        let mut newly_unlocked = Vec::new();
        for milestone in
            evaluate_achievements(&achievement_policy_for_store(&self.store, &guild_text), xp)
        {
            if self
                .store
                .unlock_achievement(
                    &guild_text,
                    user_id,
                    milestone.key,
                    milestone.threshold,
                    Utc::now().timestamp_millis(),
                )
                .unwrap_or(false)
            {
                newly_unlocked.push(format!("{} ({} XP)", milestone.label, milestone.threshold));
                if let Some(role_id) =
                    achievement_reward_role_for_store(&self.store, &guild_text, milestone.key)
                {
                    self.apply_achievement_reward_role(ctx, guild_id, user_id, role_id)
                        .await;
                }
            }
        }
        if newly_unlocked.is_empty() {
            return;
        }
        let channel = source_channel.or_else(|| {
            setting_u64_optional(
                &self.store,
                &guild_text,
                "community.levels.announce_channel",
            )
            .map(ChannelId::new)
        });
        let Some(channel) = channel else {
            return;
        };
        let _ = channel
            .say(
                &ctx.http,
                format!("🏆 <@{user_id}> unlocked: {}", newly_unlocked.join(", ")),
            )
            .await;
    }

    /// Assign an optional achievement reward role after the unlock has been
    /// persisted.  Discord remains the source of truth for role manageability;
    /// a stale/deleted/managed role is reported to the activity log instead of
    /// turning an otherwise valid XP award into a failed command.
    async fn apply_achievement_reward_role(
        &self,
        ctx: &Context,
        guild_id: serenity::all::GuildId,
        user_id: &str,
        role_id: u64,
    ) {
        if role_id == 0 {
            return;
        }
        let Ok(user_id) = user_id.parse::<u64>() else {
            return;
        };
        let role = match guild_id.roles(&ctx.http).await {
            Ok(mut roles) => roles.remove(&RoleId::new(role_id)),
            Err(error) => {
                warn!(%guild_id, %error, role_id, "could not inspect achievement reward role");
                return;
            }
        };
        let Some(role) = role else {
            let _ = self.store.record_activity(
                &guild_id.to_string(),
                "achievement_reward",
                &user_id.to_string(),
                None,
                Some(&role_id.to_string()),
                &serde_json::json!({"status":"role_not_found"}).to_string(),
            );
            return;
        };
        if role.managed {
            let _ = self.store.record_activity(
                &guild_id.to_string(),
                "achievement_reward",
                &user_id.to_string(),
                None,
                Some(&role_id.to_string()),
                &serde_json::json!({"status":"managed_role"}).to_string(),
            );
            return;
        }
        let Ok(member) = guild_id
            .member(&ctx.http, serenity::all::UserId::new(user_id))
            .await
        else {
            return;
        };
        if member
            .roles
            .iter()
            .any(|existing| existing.get() == role_id)
        {
            return;
        }
        let result = member.add_role(&ctx.http, role.id).await;
        let status = if let Err(error) = result {
            warn!(%guild_id, %error, role_id, user_id, "failed to assign achievement reward role");
            "discord_rejected"
        } else {
            "assigned"
        };
        let _ = self.store.record_activity(
            &guild_id.to_string(),
            "achievement_reward",
            &user_id.to_string(),
            None,
            Some(&role_id.to_string()),
            &serde_json::json!({"status":status,"roleId":role_id}).to_string(),
        );
    }

    async fn apply_level_rewards(
        &self,
        ctx: &Context,
        guild_id: serenity::all::GuildId,
        user_id: &str,
        level: i64,
    ) {
        let mut rewards = setting_string(
            &self.store,
            &guild_id.to_string(),
            "community.levels.level_roles",
        )
        .unwrap_or_default()
        .split(',')
        .filter_map(|entry| {
            let (raw_level, raw_role) = entry.trim().split_once('=')?;
            Some((
                raw_level.trim().parse::<i64>().ok()?,
                raw_role.trim().parse::<u64>().ok()?,
            ))
        })
        .filter(|(reward_level, _)| *reward_level > 0 && *reward_level <= level)
        .collect::<Vec<_>>();
        if rewards.is_empty() {
            return;
        }
        rewards.sort_unstable_by_key(|(reward_level, _)| *reward_level);
        let Ok(user_id) = user_id.parse::<u64>() else {
            return;
        };
        let Ok(member) = guild_id
            .member(&ctx.http, serenity::all::UserId::new(user_id))
            .await
        else {
            return;
        };
        let stack_roles = setting_bool(
            &self.store,
            &guild_id.to_string(),
            "community.levels.stack_roles",
            true,
        );
        let desired = if stack_roles {
            rewards
                .iter()
                .map(|(_, role_id)| *role_id)
                .collect::<Vec<_>>()
        } else {
            vec![
                rewards
                    .last()
                    .map(|(_, role_id)| *role_id)
                    .unwrap_or_default(),
            ]
        };
        if !stack_roles {
            for (_, role_id) in &rewards {
                if !desired.contains(role_id) {
                    let _ = member.remove_role(&ctx.http, RoleId::new(*role_id)).await;
                }
            }
        }
        for role_id in desired {
            if role_id != 0
                && !member
                    .roles
                    .iter()
                    .any(|existing| existing.get() == role_id)
            {
                let _ = member.add_role(&ctx.http, RoleId::new(role_id)).await;
            }
        }
    }

    async fn effective_plan(&self, user_id: &str, guild_id: Option<&str>) -> Plan {
        let Some(client) = &self.entitlements else {
            return Plan::Free;
        };
        match client.resolve(user_id, guild_id).await {
            Ok(snapshot)
                if snapshot.active
                    && snapshot
                        .expires_at
                        .is_none_or(|expires_at| expires_at > Utc::now()) =>
            {
                snapshot.plan
            }
            Ok(_) | Err(_) => Plan::Free,
        }
    }

    async fn send_rank_card(&self, ctx: &Context, command: &CommandInteraction) -> Result<()> {
        let Some(guild_id) = command.guild_id else {
            return respond(ctx, command, "Este comando só pode ser usado num servidor.").await;
        };
        if !feature_enabled(&self.store, &guild_id.to_string(), "community.levels", None) {
            return respond(
                ctx,
                command,
                "Levels & XP is disabled in this server. Enable it in the dashboard first.",
            )
            .await;
        }
        let user_id = command
            .data
            .options
            .iter()
            .find_map(|option| match option.value {
                CommandDataOptionValue::User(user) => Some(user),
                _ => None,
            })
            .unwrap_or(command.user.id);
        let profile = if user_id == command.user.id {
            command.user.clone()
        } else {
            ctx.http.get_user(user_id).await?
        };
        let guild_text = guild_id.to_string();
        let user_text = user_id.to_string();
        let xp = self.store.level_for(&guild_text, &user_text)?;
        let level = (xp / 100) + 1;
        let rank = self.store.level_rank(&guild_text, &user_text)?;
        let premium = matches!(
            self.effective_plan(&user_text, Some(&guild_text)).await,
            Plan::Premium { .. }
        );
        let config = rank_card::config_for_plan(
            self.store.get_setting(&guild_text, "community.rank_card")?,
            premium,
        );
        let avatar_url = profile.face();
        let svg =
            rank_card::render_rank_card(&config, &profile.name, Some(&avatar_url), rank, level, xp);
        command
            .edit_response(
                ctx,
                EditInteractionResponse::new()
                    .content(format!("{} · level {} · {} XP", profile.name, level, xp))
                    .allowed_mentions(CreateAllowedMentions::new())
                    .new_attachment(CreateAttachment::bytes(svg.into_bytes(), "rank-card.svg")),
            )
            .await?;
        Ok(())
    }

    async fn handle_command(&self, ctx: &Context, command: &CommandInteraction) -> Result<()> {
        if let Some(required) = required_permission(command.data.name.as_str()) {
            let permissions = command
                .member
                .as_deref()
                .and_then(|member| member.permissions)
                .unwrap_or_else(Permissions::empty);
            if !permissions.contains(required) && !permissions.contains(Permissions::ADMINISTRATOR)
            {
                return respond(
                    ctx,
                    command,
                    "Não tens a permissão necessária para este comando.",
                )
                .await;
            }
        }
        if let Some(guild_id) = command.guild_id
            && let Some(feature_key) = command_feature_key(command.data.name.as_str())
            && !feature_enabled(&self.store, &guild_id.to_string(), feature_key, None)
        {
            let message = format!(
                "This command is disabled because **{}** is disabled in this server. Enable it in the dashboard first.",
                feature_title(feature_key)
            );
            return respond(ctx, command, &message).await;
        }
        if let Some(guild_id) = command.guild_id
            && is_moderation_command(command.data.name.as_str())
            && feature_explicitly_disabled(
                &self.store,
                &guild_id.to_string(),
                "management.moderation",
            )
        {
            return respond(
                ctx,
                command,
                "Manual moderation is disabled in this server. Enable Moderation in the dashboard first.",
            )
            .await;
        }
        if command.data.name == "embed" {
            let Some(guild_id) = command.guild_id else {
                return respond(ctx, command, "This command can only be used in a server.").await;
            };
            let guild_text = guild_id.to_string();
            if !feature_enabled(&self.store, &guild_text, "utility.embeds", None) {
                return respond(
                    ctx,
                    command,
                    "Embeds are disabled in this server. Enable them in the dashboard.",
                )
                .await;
            }
            let config = serde_json::json!({
                "maxDescription": setting_u64(
                    &self.store,
                    &guild_text,
                    "utility.embeds.max_description",
                    2_000,
                ),
                "defaultColor": setting_string(
                    &self.store,
                    &guild_text,
                    "utility.embeds.default_color",
                )
                .unwrap_or_default(),
                "defaultFooter": setting_string(
                    &self.store,
                    &guild_text,
                    "utility.embeds.default_footer",
                )
                .unwrap_or_default(),
            });
            let decision = evaluate_embed(
                &config,
                option_string(command, "title").unwrap_or_default(),
                option_string(command, "description").unwrap_or_default(),
                option_string(command, "color"),
                option_string(command, "footer"),
            );
            if !decision.allowed {
                return respond(ctx, command, &decision.explanation).await;
            }
            let mut embed = CreateEmbed::new()
                .title(decision.title)
                .description(decision.description);
            if let Some(color) = decision.color.as_deref().and_then(parse_embed_colour) {
                embed = embed.colour(color);
            }
            if !decision.footer.is_empty() {
                embed = embed.footer(CreateEmbedFooter::new(decision.footer));
            }
            command
                .channel_id
                .send_message(
                    &ctx.http,
                    CreateMessage::new()
                        .embed(embed)
                        .allowed_mentions(CreateAllowedMentions::new()),
                )
                .await?;
            return respond(ctx, command, "Embed published.").await;
        }
        let content = match command.data.name.as_str() {
            "ping" => "Pong — Vozen Helper is online.".to_string(),
            "language" => {
                let Some(guild_id) = command.guild_id else {
                    return respond(ctx, command, "This command can only be used in a server.").await;
                };
                let guild_id = guild_id.to_string();
                match option_string(command, "locale") {
                    Some(locale) => {
                        let Some((code, label)) = helper_locale(locale) else {
                            return respond(
                                ctx,
                                command,
                                "Unsupported language. Choose one of the languages offered by `/language`.",
                            )
                            .await;
                        };
                        self.store
                            .set_setting(&guild_id, HELPER_LANGUAGE_SETTING, code)?;
                        format!("Helper language set to {label}.")
                    }
                    None => {
                        let locale = helper_locale_for_guild(&self.store, &guild_id)?;
                        let (_, label) = helper_locale(locale)
                            .expect("the configured Helper locale must be supported");
                        format!(
                            "Helper language: {label}. Use `/language locale` to change it."
                        )
                    }
                }
            }
            "help" => {
                let guild_text = command.guild_id.map(|guild_id| guild_id.to_string());
                if let Some(guild_id) = guild_text.as_deref()
                    && !feature_enabled(&self.store, guild_id, "utility.help", None)
                {
                    return respond(ctx, command, "Help is disabled in this server.").await;
                }
                let help_config = serde_json::json!({
                    "showModules": guild_text.as_deref().is_none_or(|guild_id| {
                        setting_bool(&self.store, guild_id, "utility.help.show_modules", true)
                    }),
                    "showDashboard": guild_text.as_deref().is_none_or(|guild_id| {
                        setting_bool(&self.store, guild_id, "utility.help.show_dashboard", true)
                    }),
                });
                let decision = evaluate_help(&help_config);
                let mut message = "Vozen Helper: Core, Studio, Security, Support, Events, Community, Automate and Insights.".to_string();
                if decision.show_modules {
                    message.push_str(" Use /modules to see what is enabled.");
                }
                if decision.show_dashboard {
                    message.push_str(" Use /dashboard to configure your server.");
                }
                message
            }
            "setup" => {
                let Some(guild_id) = command.guild_id else {
                    return respond(ctx, command, "Este comando só pode ser usado num servidor.").await;
                };
                let modules = ["security", "support", "events", "community", "automate", "insights"];
                let selected = modules
                    .iter()
                    .filter_map(|module| {
                        option_bool(command, module)
                            .filter(|enabled| *enabled)
                            .map(|_| *module)
                    })
                    .collect::<Vec<_>>();
                for module in &selected {
                    self.store.set_setting(
                        &guild_id.to_string(),
                        &format!("core.module.{module}.enabled"),
                        "true",
                    )?;
                }
                self.store.set_setting(
                    &guild_id.to_string(),
                    "core.setup.completed",
                    if selected.is_empty() { "false" } else { "true" },
                )?;
                if selected.is_empty() {
                    "Setup guiado: escolhe pelo menos um módulo (Security, Support, Events, Community, Automate ou Insights) e executa novamente. Depois confirma as permissões com `/permissions`.".to_string()
                } else {
                    format!("Setup saved for: **{}**. Next step: `/permissions` and then configure each module.", selected.join(", "))
                }
            }
            "modules" => {
                let Some(guild_id) = command.guild_id else {
                    return respond(ctx, command, "Este comando só pode ser usado num servidor.").await;
                };
                let modules = ["core", "studio", "security", "support", "events", "community", "automate", "insights"];
                modules
                    .iter()
                    .map(|module| {
                        let enabled = self
                            .store
                            .get_setting(&guild_id.to_string(), &format!("core.module.{module}.enabled"))
                            .ok()
                            .flatten()
                            .is_some_and(|value| value == "true")
                            || *module == "core";
                        format!("{} **{}**", if enabled { "✅" } else { "◻️" }, module)
                    })
                    .collect::<Vec<_>>()
                    .join(" · ")
            }
            "status" => {
                let Some(guild_id) = command.guild_id else {
                    return respond(ctx, command, "Este comando só pode ser usado num servidor.").await;
                };
                let setup = self
                    .store
                    .get_setting(&guild_id.to_string(), "core.setup.completed")?
                    .is_some_and(|value| value == "true");
                let configured = ["security", "support", "events", "community", "automate", "insights"]
                    .iter()
                    .filter(|module| {
                        self.store
                            .get_setting(&guild_id.to_string(), &format!("core.module.{module}.enabled"))
                            .ok()
                            .flatten()
                            .is_some_and(|value| value == "true")
                    })
                    .copied()
                    .collect::<Vec<_>>();
                format!("Setup: **{}** · Modules: **{}** · Guild isolation enabled · Privacy export/delete available", if setup { "complete" } else { "pending" }, if configured.is_empty() { "none".to_string() } else { configured.join(", ") })
            }
            "dashboard" => "Dashboard: https://helper.vozen.org (the endpoint remains disabled until the approved rollout).".to_string(),
            "plan" => {
                if let Some(client) = &self.entitlements {
                    match client.resolve(&command.user.id.to_string(), command.guild_id.map(|id| id.to_string()).as_deref()).await {
                        Ok(snapshot) => { let label = match &snapshot.plan { helper_contracts::Plan::Free => "Free", helper_contracts::Plan::Plus => "Plus", helper_contracts::Plan::Premium { .. } => "Premium" }; format!("Plano {label} · {} guild(s) · entitlements v{}.", snapshot.plan.guild_limit(), snapshot.version) },
                        Err(error) => { tracing::warn!(%error, "central entitlement lookup failed"); "Unable to check the plan right now; Helper is keeping the last safe snapshot.".to_string() }
                    }
                } else { "Central entitlements are not configured in this installation yet.".to_string() }
            }
            "privacy" => {
                let Some(guild_id) = command.guild_id else {
                    return respond(ctx, command, "Este comando só pode ser usado num servidor.").await;
                };
                let guild_text = guild_id.to_string();
                if !feature_enabled(&self.store, &guild_text, "management.privacy", None) {
                    return respond(ctx, command, "Privacy tools are disabled in this server.").await;
                }
                let allow_export = setting_bool(
                    &self.store,
                    &guild_text,
                    "management.privacy.allow_member_export",
                    true,
                );
                let allow_erase = setting_bool(
                    &self.store,
                    &guild_text,
                    "management.privacy.allow_member_erase",
                    true,
                );
                let max_export_bytes = setting_u64(
                    &self.store,
                    &guild_text,
                    "management.privacy.max_export_bytes",
                    1_000_000,
                )
                .clamp(65_536, 10_000_000) as usize;
                let subcommand = command.data.options.first().map(|option| option.name.as_str());
                let privacy_config = serde_json::json!({
                    "allowMemberExport": allow_export,
                    "allowMemberErase": allow_erase,
                    "maxExportBytes": max_export_bytes,
                });
                match subcommand {
                    Some("erase") => {
                        let decision = evaluate_privacy(&privacy_config, "erase");
                        if !decision.allowed {
                            return respond(ctx, command, &decision.explanation).await;
                        }
                        let result = self.store.purge_user(&guild_text, &command.user.id.to_string())?;
                        format!("Voluntary data deleted. Moderation records, infractions and quarantine were retained for audit. Result: {result}")
                    }
                    _ => {
                        let decision = evaluate_privacy(&privacy_config, "export");
                        if !decision.allowed {
                            return respond(ctx, command, &decision.explanation).await;
                        }
                        let export = self.store.export_user(&guild_text, &command.user.id.to_string())?;
                        let bytes = serde_json::to_vec_pretty(&export)?;
                        if bytes.len() > max_export_bytes {
                            return respond(ctx, command, "Your export is larger than this server's configured limit.").await;
                        }
                        let dm = command.user.create_dm_channel(&ctx.http).await;
                        match dm {
                            Ok(channel) => {
                                channel.send_message(
                                    &ctx.http,
                                    CreateMessage::new()
                                        .content("Here is your Vozen Helper data export.")
                                        .add_file(CreateAttachment::bytes(bytes, "my-vozen-data.json")),
                                ).await?;
                                "Enviei os teus dados por mensagem privada.".to_string()
                            }
                            Err(_) => "I could not send a direct message. Enable DMs and try again.".to_string(),
                        }
                    }
                }
            }
            "permissions" => permission_passport_message(),
            "cases" => {
                if let Some(guild_id) = command.guild_id {
                    let cases = self.store.recent_cases(&guild_id.to_string(), 10)?;
                    if cases.is_empty() { "There are no cases in this server yet.".to_string() } else { cases.into_iter().map(|case_record| format!("#{} {} <@{}>: {}", case_record.id, case_record.kind, case_record.target_id, case_record.reason)).collect::<Vec<_>>().join("\n") }
                } else { "Este comando só pode ser usado num servidor.".to_string() }
            }
            "modlogs" => {
                let Some(guild_id) = command.guild_id else {
                    return respond(ctx, command, "Este comando só pode ser usado num servidor.").await;
                };
                let Some(target) = command.data.options.iter().find_map(|option| match option.value {
                    CommandDataOptionValue::User(user) => Some(user),
                    _ => None,
                }) else {
                    return respond(ctx, command, "Indica um membro.").await;
                };
                let cases = self.store.cases_for_target(&guild_id.to_string(), &target.to_string(), 50)?;
                if cases.is_empty() {
                    format!("There are no cases for <@{}>.", target)
                } else {
                    cases.into_iter().map(|case_record| format!("#{} {}: {}", case_record.id, case_record.kind, case_record.reason)).collect::<Vec<_>>().join("\n")
                }
            }
            "warn" => {
                if let Some(guild_id) = command.guild_id {
                    let target = command.data.options.iter().find_map(|option| match &option.value { CommandDataOptionValue::User(user) => Some(*user), _ => None });
                    if let Some(target) = target {
                        let reason = command.data.options.iter().find_map(|option| match &option.value { CommandDataOptionValue::String(value) => Some(value.as_str()), _ => None }).unwrap_or("");
                        let decision = moderation_decision(
                            &self.store,
                            &guild_id.to_string(),
                            "warn",
                            reason,
                            None,
                        );
                        if !decision.allowed {
                            return respond(ctx, command, &decision.explanation).await;
                        }
                        let reason = if reason.trim().is_empty() { "No reason provided" } else { reason };
                        let case_id = self.store.record_case(&guild_id.to_string(), "warn", &target.to_string(), &command.user.id.to_string(), reason, None)?;
                        format!("Warning created as case #{case_id} for <@{}>.", target)
                    } else { "Indica um membro.".to_string() }
                } else { "Este comando só pode ser usado num servidor.".to_string() }
            }
            "slowmode" => {
                let raw_seconds = command.data.options.iter().find_map(|option| match option.value {
                    CommandDataOptionValue::Integer(value) if option.name == "seconds" => Some(value),
                    _ => None,
                }).unwrap_or(0);
                let seconds = raw_seconds.clamp(0, 21_600) as u16;
                command
                    .channel_id
                    .edit(&ctx.http, EditChannel::new().rate_limit_per_user(seconds))
                    .await?;
                format!("Slowmode set to {} seconds.", seconds)
            }
            "userinfo" => {
                let Some(user_id) = command.data.options.iter().find_map(|option| match option.value {
                    CommandDataOptionValue::User(user) => Some(user),
                    _ => None,
                }) else {
                    return respond(ctx, command, "Indica um utilizador.").await;
                };
                let user = ctx.http.get_user(user_id).await?;
                format!("{} (<@{}>) · account created at {}.", user.name, user.id, user.id.created_at().unix_timestamp())
            }
            "violation" | "note" => {
                let Some(guild_id) = command.guild_id else {
                    return respond(ctx, command, "Este comando só pode ser usado num servidor.").await;
                };
                let Some(target) = command.data.options.iter().find_map(|option| match option.value {
                    CommandDataOptionValue::User(user) => Some(user),
                    _ => None,
                }) else {
                    return respond(ctx, command, "Indica um membro.").await;
                };
                let reason = if command.data.name == "violation" {
                    let rule = option_string(command, "rule").unwrap_or("unspecified");
                    let details = option_string(command, "details").unwrap_or("Sem detalhes");
                    format!("{rule}: {details}")
                } else {
                    option_string(command, "content").unwrap_or("No content").to_string()
                };
                if reason.len() > 500 {
                    return respond(ctx, command, "O conteúdo não pode exceder 500 caracteres.").await;
                }
                let case_id = self.store.record_case(&guild_id.to_string(), &command.data.name, &target.to_string(), &command.user.id.to_string(), &reason, None)?;
                format!("Record #{case_id} created for <@{}>.", target)
            }
            "reason" => {
                let Some(guild_id) = command.guild_id else {
                    return respond(ctx, command, "Este comando só pode ser usado num servidor.").await;
                };
                let case_id = command.data.options.iter().find_map(|option| match option.value {
                    CommandDataOptionValue::Integer(value) if option.name == "case" => Some(value),
                    _ => None,
                }).unwrap_or(0);
                let reason = option_string(command, "reason").unwrap_or("Sem motivo");
                if self.store.update_case_reason(&guild_id.to_string(), case_id, reason)? {
                    format!("Reason for case #{case_id} updated.")
                } else {
                    "Case not found in this server.".to_string()
                }
            }
            "untimeout" => {
                let Some(guild_id) = command.guild_id else {
                    return respond(ctx, command, "Este comando só pode ser usado num servidor.").await;
                };
                let Some(target) = command.data.options.iter().find_map(|option| match option.value {
                    CommandDataOptionValue::User(user) => Some(user),
                    _ => None,
                }) else {
                    return respond(ctx, command, "Indica um membro.").await;
                };
                let result = guild_id
                    .edit_member(&ctx.http, target, serenity::all::EditMember::new().enable_communication())
                    .await;
                match result {
                    Ok(_) => format!("Timeout removed for <@{}>.", target),
                    Err(error) => {
                        tracing::warn!(%error, "untimeout failed");
                        "Unable to remove the timeout; check permissions.".to_string()
                    }
                }
            }
            "unban" => {
                let Some(guild_id) = command.guild_id else {
                    return respond(ctx, command, "Este comando só pode ser usado num servidor.").await;
                };
                let Some(raw_user_id) = option_string(command, "user_id") else {
                    return respond(ctx, command, "Indica um ID de utilizador.").await;
                };
                let Ok(user_id) = raw_user_id.parse::<u64>() else {
                    return respond(ctx, command, "ID de utilizador inválido.").await;
                };
                match guild_id.unban(&ctx.http, serenity::all::UserId::new(user_id)).await {
                    Ok(()) => "User unbanned.".to_string(),
                    Err(error) => {
                        tracing::warn!(%error, "unban failed");
                        "Unable to remove the ban.".to_string()
                    }
                }
            }
            "purge" => {
                let raw_count = command.data.options.iter().find_map(|option| match option.value {
                    CommandDataOptionValue::Integer(value) if option.name == "count" => Some(value),
                    _ => None,
                }).unwrap_or(0);
                let Some(guild_id) = command.guild_id else {
                    return respond(ctx, command, "This command can only be used in a server.").await;
                };
                let decision = moderation_decision(
                    &self.store,
                    &guild_id.to_string(),
                    "purge",
                    "",
                    Some(raw_count),
                );
                if !decision.allowed {
                    return respond(ctx, command, &decision.explanation).await;
                }
                let count = decision.effective_count.unwrap_or(1) as u8;
                let messages = command.channel_id.messages(&ctx.http, serenity::all::GetMessages::new().limit(count)).await?;
                if messages.is_empty() {
                    "No messages found to delete.".to_string()
                } else {
                    let ids: Vec<_> = messages.iter().map(|message| message.id).collect();
                    command.channel_id.delete_messages(&ctx.http, ids).await?;
                    format!("{} messages deleted.", messages.len())
                }
            }
            "tempban" | "softban" => {
                let Some(guild_id) = command.guild_id else {
                    return respond(ctx, command, "Este comando só pode ser usado num servidor.").await;
                };
                let Some(target) = command.data.options.iter().find_map(|option| match option.value {
                    CommandDataOptionValue::User(user) => Some(user),
                    _ => None,
                }) else {
                    return respond(ctx, command, "Indica um membro.").await;
                };
                let reason = option_string(command, "reason").unwrap_or("");
                let decision = moderation_decision(
                    &self.store,
                    &guild_id.to_string(),
                    &command.data.name,
                    reason,
                    None,
                );
                if !decision.allowed {
                    return respond(ctx, command, &decision.explanation).await;
                }
                let reason = if reason.trim().is_empty() { "No reason provided" } else { reason };
                let action = guild_id.ban_with_reason(&ctx.http, target, 0, reason).await;
                if let Err(error) = action {
                    tracing::warn!(%error, action = %command.data.name, "ban action failed");
                    return respond(ctx, command, "Nao foi possivel executar o ban; confirma as permissoes e a hierarquia.").await;
                }
                if command.data.name == "softban" {
                    let _ = guild_id.unban(&ctx.http, target).await;
                    let case_id = self.store.record_case(&guild_id.to_string(), "softban", &target.to_string(), &command.user.id.to_string(), reason, None)?;
                    format!("Softban completed as case #{case_id} for <@{}>.", target)
                } else {
                    let Some(delay) = parse_duration(option_string(command, "duration").unwrap_or_default()) else {
                        let _ = guild_id.unban(&ctx.http, target).await;
                        return respond(ctx, command, "Duração inválida. Usa 10m, 2h ou 1d.").await;
                    };
                    let case_id = self.store.record_case(&guild_id.to_string(), "tempban", &target.to_string(), &command.user.id.to_string(), reason, Some(delay))?;
                    self.store.schedule_typed(&guild_id.to_string(), "unban", &target.to_string(), chrono::Utc::now().timestamp_millis() + delay, "")?;
                    format!("Tempban completed as case #{case_id} for <@{}>; expires in {}.", target, format_duration(delay))
                }
            }
            "kick" | "ban" | "timeout" => {
                let Some(guild_id) = command.guild_id else {
                    return respond(ctx, command, "Este comando só pode ser usado num servidor.").await;
                };
                let Some(target) = command.data.options.iter().find_map(|option| match &option.value {
                    CommandDataOptionValue::User(user) => Some(*user),
                    _ => None,
                }) else {
                    return respond(ctx, command, "Indica um membro.").await;
                };
                let reason = command.data.options.iter().find_map(|option| match &option.value {
                    CommandDataOptionValue::String(value) => Some(value.as_str()),
                    _ => None,
                }).unwrap_or("");
                let decision = moderation_decision(
                    &self.store,
                    &guild_id.to_string(),
                    &command.data.name,
                    reason,
                    None,
                );
                if !decision.allowed {
                    return respond(ctx, command, &decision.explanation).await;
                }
                let reason = if reason.trim().is_empty() { "No reason provided" } else { reason };
                let action = if command.data.name == "kick" {
                    guild_id.kick_with_reason(&ctx.http, target, reason).await
                } else if command.data.name == "ban" {
                    guild_id.ban_with_reason(&ctx.http, target, 0, reason).await
                } else {
                    let seconds = command.data.options.iter().find_map(|option| match option.value {
                        CommandDataOptionValue::Integer(value) => Some(value),
                        _ => None,
                    }).unwrap_or(600).clamp(1, 28 * 24 * 60 * 60);
                    let until = (chrono::Utc::now() + chrono::Duration::seconds(seconds)).to_rfc3339();
                    guild_id.edit_member(&ctx.http, target, serenity::all::EditMember::new().disable_communication_until(until)).await.map(|_| ())
                };
                match action {
                    Ok(()) => {
                        let case_id = self.store.record_case(&guild_id.to_string(), &command.data.name, &target.to_string(), &command.user.id.to_string(), reason, None)?;
                        format!("Action {} completed as case #{case_id} for <@{}>.", command.data.name, target)
                    }
                    Err(error) => {
                        tracing::warn!(%error, action = %command.data.name, "discord moderation action failed");
                        "Unable to perform the action; check permissions and role hierarchy.".to_string()
                    }
                }
            }
            "afk" => {
                let Some(guild_id) = command.guild_id else {
                    return respond(ctx, command, "Este comando só pode ser usado num servidor.").await;
                };
                let reason = command.data.options.iter().find_map(|option| match &option.value {
                    CommandDataOptionValue::String(value) => Some(value.as_str()),
                    _ => None,
                });
                if let Some(reason) = reason.filter(|value| !value.trim().is_empty()) {
                    self.store.set_afk(&guild_id.to_string(), &command.user.id.to_string(), reason)?;
                    format!("AFK status set: {reason}")
                } else if self.store.clear_afk(&guild_id.to_string(), &command.user.id.to_string())? {
                    "AFK status removed.".to_string()
                } else {
                    "You did not have an AFK status set.".to_string()
                }
            }
            "remind" => {
                let Some(guild_id) = command.guild_id else {
                    return respond(ctx, command, "Este comando só pode ser usado num servidor.").await;
                };
                let guild_text = guild_id.to_string();
                if !feature_enabled(&self.store, &guild_text, "utility.reminders", None) {
                    return respond(
                        ctx,
                        command,
                        "Reminders are disabled in this server. Enable them in the dashboard.",
                    )
                    .await;
                }
                let time = option_string(command, "time").unwrap_or_default();
                let text = option_string(command, "text").unwrap_or_default();
                let repeat = option_string(command, "repeat");
                let policy = reminder_policy_for_store(&self.store, &guild_text);
                let timezone = policy.timezone.clone();
                let now_ms = chrono::Utc::now().timestamp_millis();
                let Some(delay) = parse_reminder_delay(time, &timezone, now_ms) else {
                    return respond(
                        ctx,
                        command,
                        "Invalid reminder time. Use a duration such as 10m, 2h or 1d, or a local 24-hour time such as 09:30.",
                    )
                    .await;
                };
                let decision = evaluate_reminder(
                    &policy,
                    &ReminderObservation {
                        delay_ms: delay,
                        text: text.to_owned(),
                        repeat: repeat.map(str::to_owned),
                        timezone: timezone.clone(),
                    },
                );
                if !decision.allowed {
                    let message = match decision.reason_code {
                        "invalid_timezone" => "The server reminder timezone is invalid; ask an administrator to choose a supported UTC offset.",
                        "recurring_disabled" => "Recurring reminders are disabled in this server's dashboard.",
                        "invalid_repeat" => "Choose daily or weekly for repeat.",
                        "delay_exceeds_limit" => "That reminder is beyond the server's configured maximum delay.",
                        "text_exceeds_limit" => "The reminder is longer than the server's configured limit.",
                        _ => "That reminder cannot be scheduled with the current server policy.",
                    };
                    return respond(ctx, command, message).await;
                }
                let payload = serde_json::json!({
                    "channel_id": command.channel_id.to_string(),
                    "text": text,
                    "repeat": repeat,
                    "timezone": timezone,
                    "local_time": parse_clock_time(time).map(|(hour, minute)| format!("{hour:02}:{minute:02}")),
                    "remaining": repeat.as_ref().map(|_| decision.remaining),
                });
                let id = self.store.schedule(
                    &guild_text,
                    &command.user.id.to_string(),
                    now_ms + delay,
                    &payload.to_string(),
                )?;
                if repeat.is_some() {
                    format!("Reminder #{id} scheduled with bounded repeats.")
                } else {
                    format!("Reminder #{id} scheduled.")
                }
            }
            "birthday-set" => {
                let Some(guild_id) = command.guild_id else {
                    return respond(ctx, command, "This command can only be used in a server.").await;
                };
                let guild_text = guild_id.to_string();
                if !feature_enabled(&self.store, &guild_text, "community.birthdays", None) {
                    return respond(ctx, command, "Birthdays are disabled in this server. Enable them in the dashboard.").await;
                }
                let month = option_i64(command, "month").unwrap_or_default();
                let day = option_i64(command, "day").unwrap_or_default();
                let valid_day = match month {
                    1 | 3 | 5 | 7 | 8 | 10 | 12 => (1..=31).contains(&day),
                    4 | 6 | 9 | 11 => (1..=30).contains(&day),
                    2 => (1..=29).contains(&day),
                    _ => false,
                };
                if !valid_day {
                    return respond(ctx, command, "Use a real calendar day and month for the birthday.").await;
                }
                self.store.set_birthday(&guild_text, &command.user.id.to_string(), month as u32, day as u32)?;
                "Birthday saved privately as day and month. You can remove it at any time.".to_string()
            }
            "birthday-remove" => {
                let Some(guild_id) = command.guild_id else {
                    return respond(ctx, command, "This command can only be used in a server.").await;
                };
                let guild_text = guild_id.to_string();
                if !feature_enabled(&self.store, &guild_text, "community.birthdays", None) {
                    return respond(ctx, command, "Birthdays are disabled in this server. Enable them in the dashboard.").await;
                }
                if self.store.remove_birthday(&guild_text, &command.user.id.to_string())? {
                    "Your birthday was removed.".to_string()
                } else {
                    "You do not have a birthday saved in this server.".to_string()
                }
            }
            "tag" => {
                let Some(guild_id) = command.guild_id else {
                    return respond(ctx, command, "Este comando só pode ser usado num servidor.").await;
                };
                if !feature_enabled(&self.store, &guild_id.to_string(), "management.custom_commands", None) {
                    return respond(ctx, command, "Custom commands are disabled in this server. Enable them in the dashboard.").await;
                }
                let name = option_string(command, "name").unwrap_or_default().to_lowercase();
                match self.store.get_tag(&guild_id.to_string(), &name)? {
                    Some(tag) => tag.content.replace("{user}", &format!("<@{}>", command.user.id)),
                    None => "Tag not found.".to_string(),
                }
            }
            "tags" => {
                let Some(guild_id) = command.guild_id else {
                    return respond(ctx, command, "Este comando só pode ser usado num servidor.").await;
                };
                if !feature_enabled(&self.store, &guild_id.to_string(), "management.custom_commands", None) {
                    return respond(ctx, command, "Custom commands are disabled in this server. Enable them in the dashboard.").await;
                }
                let max_tags = setting_u64(&self.store, &guild_id.to_string(), "management.custom_commands.max_tags", 100).clamp(1, 100) as u32;
                let names = self.store.list_tags(&guild_id.to_string(), max_tags)?;
                if names.is_empty() { "There are no tags yet.".to_string() } else { names.join(", ") }
            }
            "tag-set" => {
                let Some(guild_id) = command.guild_id else {
                    return respond(ctx, command, "Este comando só pode ser usado num servidor.").await;
                };
                let guild_text = guild_id.to_string();
                if !feature_enabled(&self.store, &guild_text, "management.custom_commands", None) {
                    return respond(ctx, command, "Custom commands are disabled in this server. Enable them in the dashboard.").await;
                }
                let name = option_string(command, "name").unwrap_or_default().trim().to_lowercase();
                let content = option_string(command, "content").unwrap_or_default();
                let max_response_length = setting_u64(&self.store, &guild_text, "management.custom_commands.max_response_length", 1_000).clamp(1, 2_000) as usize;
                if !(1..=32).contains(&name.len()) || content.is_empty() || content.len() > max_response_length {
                    return respond(ctx, command, "Nome ou conteúdo inválido.").await;
                }
                let existing = self.store.get_tag(&guild_text, &name)?.is_some();
                let max_tags = setting_u64(&self.store, &guild_text, "management.custom_commands.max_tags", 100).clamp(1, 100) as u32;
                if !existing && self.store.list_tags(&guild_text, max_tags.saturating_add(1))?.len() as u64 >= max_tags as u64 {
                    return respond(ctx, command, "This server has reached its custom command limit.").await;
                }
                self.store.upsert_tag(&guild_text, &name, content, &command.user.id.to_string())?;
                format!("Tag `{name}` saved.")
            }
            "tag-delete" => {
                let Some(guild_id) = command.guild_id else {
                    return respond(ctx, command, "Este comando só pode ser usado num servidor.").await;
                };
                let guild_text = guild_id.to_string();
                if !feature_enabled(&self.store, &guild_text, "management.custom_commands", None) {
                    return respond(ctx, command, "Custom commands are disabled in this server. Enable them in the dashboard.").await;
                }
                let name = option_string(command, "name").unwrap_or_default().trim().to_lowercase();
                if self.store.delete_tag(&guild_text, &name)? { format!("Tag `{name}` deleted.") } else { "Tag not found.".to_string() }
            }
            "rank" => return self.send_rank_card(ctx, command).await,
            "leaderboard-privacy" => {
                let Some(guild_id) = command.guild_id else {
                    return respond(ctx, command, "This command can only be used in a server.").await;
                };
                let guild_text = guild_id.to_string();
                if !feature_enabled(&self.store, &guild_text, "community.leaderboard", None) {
                    return respond(
                        ctx,
                        command,
                        "The XP leaderboard is disabled in this server. Enable it in the dashboard.",
                    )
                    .await;
                }
                let opt_out = option_bool(command, "opt_out").unwrap_or(false);
                self.store.set_setting(
                    &guild_text,
                    &format!("community.leaderboard.optout.{}", command.user.id),
                    if opt_out { "true" } else { "false" },
                )?;
                if opt_out {
                    "Your XP is now hidden from this server's leaderboard.".to_string()
                } else {
                    "Your XP is now visible on this server's leaderboard.".to_string()
                }
            }
            "leaderboard" => {
                let Some(guild_id) = command.guild_id else {
                    return respond(ctx, command, "Este comando só pode ser usado num servidor.").await;
                };
                let guild_text = guild_id.to_string();
                if !feature_enabled(&self.store, &guild_text, "community.leaderboard", None) {
                    return respond(
                        ctx,
                        command,
                        "The XP leaderboard is disabled in this server. Enable it in the dashboard.",
                    )
                    .await;
                }
                let max_entries = setting_u64(
                    &self.store,
                    &guild_text,
                    "community.leaderboard.max_entries",
                    10,
                )
                .clamp(1, 100) as u32;
                // Read a bounded superset before applying member opt-outs so
                // hidden rows do not make the configured limit appear empty.
                let rows = self.store.top_levels(&guild_text, 100)?;
                let public = setting_bool(
                    &self.store,
                    &guild_text,
                    "community.leaderboard.public",
                    true,
                );
                let policy = leaderboard_policy_from_json(&serde_json::json!({
                    "maxEntries": max_entries,
                    "public": public,
                }));
                let entries = rows.into_iter().map(|row| {
                    let opted_out = setting_bool(
                        &self.store,
                        &guild_text,
                        &format!("community.leaderboard.optout.{}", row.user_id),
                        false,
                    );
                    LeaderboardEntry {
                        user_id: row.user_id,
                        xp: row.xp,
                        opted_out,
                    }
                });
                let decision = evaluate_leaderboard(&policy, entries);
                if decision.entries.is_empty() {
                    "No eligible XP data yet.".to_string()
                } else {
                    decision
                        .entries
                        .into_iter()
                        .enumerate()
                        .map(|(index, row)| {
                            format!("{}. <@{}> — {} XP", index + 1, row.user_id, row.xp)
                        })
                        .collect::<Vec<_>>()
                        .join("\n")
                }
            }
            "achievements" => {
                let Some(guild_id) = command.guild_id else {
                    return respond(ctx, command, "This command can only be used in a server.").await;
                };
                let guild_text = guild_id.to_string();
                if !feature_enabled(&self.store, &guild_text, "community.achievements", None) {
                    return respond(ctx, command, "Achievements are disabled in this server. Enable them in the dashboard.").await;
                }
                let xp = self.store.level_for(&guild_text, &command.user.id.to_string())?;
                for milestone in evaluate_achievements(
                    &achievement_policy_for_store(&self.store, &guild_text),
                    xp,
                ) {
                    let _ = self.store.unlock_achievement(
                        &guild_text,
                        &command.user.id.to_string(),
                        milestone.key,
                        milestone.threshold,
                        Utc::now().timestamp_millis(),
                    );
                }
                let unlocked = self
                    .store
                    .achievements_for(&guild_text, &command.user.id.to_string())?;
                let achievements = configured_achievement_milestones(&self.store, &guild_text)
                    .into_iter()
                    .map(|(key, label, threshold)| {
                        let persisted = unlocked.iter().any(|entry| entry.achievement_key == key);
                        if persisted {
                            format!("✅ {label} ({threshold} XP)")
                        } else {
                            format!("🔒 {label} ({threshold} XP)")
                        }
                    })
                    .collect::<Vec<_>>();
                format!("Your achievements ({xp} XP):\n{}", achievements.join("\n"))
            }
            "search" => {
                let Some(guild_id) = command.guild_id else {
                    return respond(ctx, command, "This command can only be used in a server.").await;
                };
                let guild_text = guild_id.to_string();
                if !feature_enabled(&self.store, &guild_text, "utility.search", None) {
                    return respond(ctx, command, "Search is disabled in this server. Enable it in the dashboard.").await;
                }
                let provider = option_string(command, "provider")
                    .unwrap_or_default()
                    .trim()
                    .to_ascii_lowercase();
                let query = option_string(command, "query")
                    .unwrap_or_default()
                    .trim()
                    .to_string();
                let max_results = setting_u64(&self.store, &guild_text, "utility.search.max_results", 5)
                    .clamp(1, 5) as usize;
                if query.is_empty() || query.len() > 128 {
                    return respond(ctx, command, "Search text must contain between 1 and 128 characters.").await;
                }
                let wikipedia = setting_bool(&self.store, &guild_text, "utility.search.allow_wikipedia", true);
                let anilist = setting_bool(&self.store, &guild_text, "utility.search.allow_anilist", true);
                let bluesky = setting_bool(&self.store, &guild_text, "utility.search.allow_bluesky", true);
                let youtube = setting_bool(&self.store, &guild_text, "utility.search.allow_youtube", true);
                let twitch = setting_bool(&self.store, &guild_text, "utility.search.allow_twitch", true);
                let search_config = serde_json::json!({
                    "maxResults": max_results,
                    "allowWikipedia": wikipedia,
                    "allowAniList": anilist,
                    "allowBluesky": bluesky,
                    "allowYouTube": youtube,
                    "allowTwitch": twitch,
                });
                let decision = evaluate_search(&search_config, &provider, query.len());
                if !decision.allowed {
                    return respond(ctx, command, &decision.explanation).await;
                }
                let max_results = decision.max_results;
                let http = HttpClient::builder().timeout(Duration::from_secs(15)).build()?;
                match provider.as_str() {
                    "youtube" if youtube => {
                        let Some(client) = self.youtube.as_ref() else {
                            return respond(ctx, command, "YouTube search is not configured on this Helper.").await;
                        };
                        let results = client.search_videos(&query, max_results).await?;
                        if results.is_empty() {
                            "No YouTube results were found.".to_string()
                        } else {
                            format_youtube_search_results(&results)
                        }
                    }
                    "twitch" if twitch => {
                        let Some(client) = self.twitch.as_ref() else {
                            return respond(ctx, command, "Twitch search is not configured on this Helper.").await;
                        };
                        let results = client.search_channels(&query, max_results).await?;
                        if results.is_empty() {
                            "No Twitch results were found.".to_string()
                        } else {
                            format_twitch_search_results(&results)
                        }
                    }
                    "wikipedia" if wikipedia => {
                        let response = http
                            .get("https://en.wikipedia.org/w/api.php")
                            .query(&[
                                ("action", "query"),
                                ("list", "search"),
                                ("format", "json"),
                                ("utf8", "1"),
                                ("srprop", "snippet"),
                                ("srlimit", &max_results.to_string()),
                                ("srsearch", &query),
                            ])
                            .header("User-Agent", "VozenHelper/0.1 (https://vozen.org)")
                            .send()
                            .await?
                            .error_for_status()?
                            .json::<serde_json::Value>()
                            .await?;
                        let rows = response
                            .pointer("/query/search")
                            .and_then(serde_json::Value::as_array)
                            .map(|items| {
                                items
                                    .iter()
                                    .take(max_results)
                                    .filter_map(|item| {
                                        let title = item.get("title")?.as_str()?;
                                        let snippet = item
                                            .get("snippet")
                                            .and_then(serde_json::Value::as_str)
                                            .unwrap_or("")
                                            .replace("<span class=\"searchmatch\">", "")
                                            .replace("</span>", "");
                                        Some(format!("**{title}** — {snippet}"))
                                    })
                                    .collect::<Vec<_>>()
                            })
                            .unwrap_or_default();
                        if rows.is_empty() { "No Wikipedia results were found.".to_string() } else { rows.join("\n") }
                    }
                    "anilist" if anilist => {
                        let body = serde_json::json!({
                            "query": "query ($search: String, $perPage: Int) { Page(perPage: $perPage) { media(search: $search, type: ANIME) { title { romaji english native } siteUrl } } }",
                            "variables": {"search": query, "perPage": max_results}
                        });
                        let response = http
                            .post("https://graphql.anilist.co")
                            .header("User-Agent", "VozenHelper/0.1 (https://vozen.org)")
                            .json(&body)
                            .send()
                            .await?
                            .error_for_status()?
                            .json::<serde_json::Value>()
                            .await?;
                        let rows = response
                            .pointer("/data/Page/media")
                            .and_then(serde_json::Value::as_array)
                            .map(|items| {
                                items
                                    .iter()
                                    .take(max_results)
                                    .filter_map(|item| {
                                        let title = item.get("title")?;
                                        let display = title
                                            .get("english")
                                            .and_then(serde_json::Value::as_str)
                                            .or_else(|| title.get("romaji").and_then(serde_json::Value::as_str))
                                            .or_else(|| title.get("native").and_then(serde_json::Value::as_str))?;
                                        let url = item.get("siteUrl").and_then(serde_json::Value::as_str).unwrap_or("");
                                        Some(if url.is_empty() { format!("**{display}**") } else { format!("**{display}** — {url}") })
                                    })
                                    .collect::<Vec<_>>()
                            })
                            .unwrap_or_default();
                        if rows.is_empty() { "No AniList results were found.".to_string() } else { rows.join("\n") }
                    }
                    "bluesky" if bluesky => {
                        let response = http
                            .get("https://public.api.bsky.app/xrpc/app.bsky.feed.searchPosts")
                            .query(&[("q", query.as_str()), ("limit", &max_results.to_string())])
                            .header("User-Agent", "VozenHelper/0.1 (https://vozen.org)")
                            .send()
                            .await?
                            .error_for_status()?
                            .json::<serde_json::Value>()
                            .await?;
                        let rows = response
                            .pointer("/posts")
                            .and_then(serde_json::Value::as_array)
                            .map(|items| {
                                items
                                    .iter()
                                    .take(max_results)
                                    .filter_map(|item| {
                                        let author = item.pointer("/author/displayName")
                                            .and_then(serde_json::Value::as_str)
                                            .or_else(|| item.pointer("/author/handle").and_then(serde_json::Value::as_str))?;
                                        let record = item.get("record")?;
                                        let text = record.get("text").and_then(serde_json::Value::as_str).unwrap_or("");
                                        let uri = item.get("uri").and_then(serde_json::Value::as_str).unwrap_or("");
                                        Some(if uri.is_empty() {
                                            format!("**{author}** — {}", truncate(text, 280))
                                        } else {
                                            format!("**{author}** — {}\n{}", truncate(text, 280), uri)
                                        })
                                    })
                                    .collect::<Vec<_>>()
                            })
                            .unwrap_or_default();
                        if rows.is_empty() { "No Bluesky results were found.".to_string() } else { rows.join("\n") }
                    }
                    "youtube" | "twitch" | "wikipedia" | "anilist" | "bluesky" => "That search provider is disabled in this server's settings.".to_string(),
                    _ => "Choose an approved provider: `youtube`, `twitch`, `wikipedia`, `anilist` or `bluesky`.".to_string(),
                }
            }
            "serverstats" => {
                let Some(guild_id) = command.guild_id else {
                    return respond(ctx, command, "Este comando só pode ser usado num servidor.").await;
                };
                let guild_text = guild_id.to_string();
                if !feature_enabled(&self.store, &guild_text, "insights.stats", None) {
                    return respond(
                        ctx,
                        command,
                        "Server statistics are disabled in this server. Enable them in the dashboard.",
                    )
                    .await;
                }
                let window_days = setting_u64(
                    &self.store,
                    &guild_text,
                    "insights.stats.window_days",
                    7,
                )
                .clamp(1, 30) as u32;
                let rows = self.store.stats_for(&guild_text, window_days)?;
                let messages: i64 = rows.iter().map(|(_, messages, _, _)| messages).sum();
                format!("Messages recorded in the last {} days: {}.", rows.len(), messages)
            }
            "crypto" => {
                let Some(guild_id) = command.guild_id else {
                    return respond(ctx, command, "This command can only be used in a server.").await;
                };
                let guild_text = guild_id.to_string();
                if !feature_enabled(&self.store, &guild_text, "web3.crypto_queries", None) {
                    return respond(ctx, command, "Crypto queries are disabled in this server. Enable them in the dashboard.").await;
                }
                let configured_coins = setting_string(
                    &self.store,
                    &guild_text,
                    "web3_crypto_queries.coin_ids",
                );
                let coins = option_string(command, "coins")
                    .map(ToOwned::to_owned)
                    .or(configured_coins)
                    .unwrap_or_default();
                let ids = coins
                    .split(',')
                    .map(str::trim)
                    .filter(|id| !id.is_empty())
                    .map(ToOwned::to_owned)
                    .collect::<Vec<_>>();
                let max_results = setting_u64(
                    &self.store,
                    &guild_text,
                    "web3_crypto_queries.max_results",
                    10,
                )
                .clamp(1, 10) as usize;
                if ids.is_empty() || ids.len() > max_results {
                    return respond(ctx, command, "Choose between 1 and 10 CoinGecko coin IDs, separated by commas.").await;
                }
                let configured_currency = setting_string(
                    &self.store,
                    &guild_text,
                    "web3_crypto_queries.currency",
                );
                let currency = option_string(command, "currency")
                    .map(ToOwned::to_owned)
                    .or(configured_currency)
                    .unwrap_or_else(|| "usd".into());
                let Some(client) = self.coingecko.as_ref() else {
                    return respond(ctx, command, "The CoinGecko provider is not available right now.").await;
                };
                match client.quotes(&ids, &currency).await {
                    Ok(quotes) if quotes.is_empty() => "No price data was found for those CoinGecko IDs.".to_string(),
                    Ok(quotes) => format_crypto_quotes(&quotes),
                    Err(error) => {
                        warn!(%error, guild_id = %guild_text, "CoinGecko query failed");
                        "CoinGecko is temporarily unavailable. Please try again later.".to_string()
                    }
                }
            }
            "gas" => {
                let Some(guild_id) = command.guild_id else {
                    return respond(ctx, command, "This command can only be used in a server.").await;
                };
                let guild_text = guild_id.to_string();
                if !feature_enabled(&self.store, &guild_text, "web3.gas_tracker", None) {
                    return respond(ctx, command, "Gas tracking is disabled in this server. Enable it in the dashboard.").await;
                }
                let configured_network = setting_string(
                    &self.store,
                    &guild_text,
                    "web3.gas_tracker.network",
                );
                let network = option_string(command, "network")
                    .or(configured_network.as_deref())
                    .unwrap_or("ethereum");
                match self.gas.quote(network).await {
                    Ok(quote) => format_gas_quote(&quote),
                    Err(error) => {
                        warn!(%error, guild_id = %guild_text, network, "gas provider request failed");
                        "The configured gas provider is unavailable right now.".to_string()
                    }
                }
            }
            "emojis" => {
                let Some(guild_id) = command.guild_id else {
                    return respond(ctx, command, "This command can only be used in a server.").await;
                };
                let guild_text = guild_id.to_string();
                if !feature_enabled(&self.store, &guild_text, "utility.emojis", None) {
                    return respond(ctx, command, "Emoji inventory is disabled in this server. Enable it in the dashboard.").await;
                }
                let max_entries = setting_u64(&self.store, &guild_text, "utility.emojis.max_entries", 50).clamp(1, 100) as usize;
                let animated_only = setting_bool(&self.store, &guild_text, "utility.emojis.animated_only", false);
                let emojis = guild_id.emojis(&ctx.http).await?;
                let total_count = emojis.len() as u64;
                let animated_count = emojis.iter().filter(|emoji| emoji.animated).count() as u64;
                let emoji_config = serde_json::json!({
                    "maxEntries": max_entries,
                    "animatedOnly": animated_only,
                });
                let decision = evaluate_emojis(&emoji_config, total_count, animated_count);
                let max_entries = decision.max_entries;
                let animated_only = decision.animated_only;
                if emojis.is_empty() { "No custom emojis are configured in this server.".to_string() } else {
                    let rows = emojis.into_iter().filter(|emoji| !animated_only || emoji.animated).take(max_entries).map(|emoji| format!("{} `<:{}:{}>`", if emoji.animated { "🎞️" } else { "😀" }, emoji.name, emoji.id)).collect::<Vec<_>>();
                    if rows.is_empty() { "No emojis match the current inventory filters.".to_string() } else { rows.join("\n") }
                }
            }
            "invites" => {
                let Some(guild_id) = command.guild_id else {
                    return respond(ctx, command, "This command can only be used in a server.").await;
                };
                let guild_text = guild_id.to_string();
                if !feature_enabled(&self.store, &guild_text, "management.invite_tracker", None) {
                    return respond(ctx, command, "Invite tracking is disabled in this server. Enable it in the dashboard.").await;
                }
                let max_entries = setting_u64(&self.store, &guild_text, "management.invite_tracker.max_entries", 10).clamp(1, 50) as usize;
                let include_inviter = setting_bool(&self.store, &guild_text, "management.invite_tracker.include_inviter", true);
                let mut invites = guild_id.invites(&ctx.http).await?;
                invites.sort_by_key(|invite| std::cmp::Reverse(invite.uses));
                let invite_config = serde_json::json!({
                    "maxEntries": max_entries,
                    "includeInviter": include_inviter,
                });
                let decision = evaluate_invite_tracker(&invite_config, invites.len() as u64);
                let max_entries = decision.max_entries;
                let include_inviter = decision.include_inviter;
                let invite_text = if invites.is_empty() { "No active invites were found. The bot needs Manage Server to read them.".to_string() } else {
                    invites
                        .into_iter()
                        .take(max_entries)
                        .map(|invite| {
                            let inviter = invite.inviter.map(|user| user.name).unwrap_or_else(|| "Discord system".into());
                            if include_inviter { format!("`{}` — {} uses — {}", invite.code, invite.uses, inviter) } else { format!("`{}` — {} uses", invite.code, invite.uses) }
                        })
                        .collect::<Vec<_>>()
                        .join("\n")
                };
                let tracked = self.store.invite_attribution_summary(&guild_text, max_entries as u32)?;
                if tracked.is_empty() {
                    invite_text
                } else {
                    let tracked_text = tracked
                        .into_iter()
                        .map(|(code, joins)| format!("`{code}` — {joins} attributed join(s)"))
                        .collect::<Vec<_>>()
                        .join("\n");
                    format!("{invite_text}\n\nTracked joins:\n{tracked_text}")
                }
            }
            "balance" => {
                let Some(guild_id) = command.guild_id else {
                    return respond(ctx, command, "This command can only be used in a server.").await;
                };
                let guild_text = guild_id.to_string();
                if !feature_enabled(&self.store, &guild_text, "community.economy", None) {
                    return respond(ctx, command, "Economy is disabled in this server. Enable it in the dashboard.").await;
                }
                let account = self.store.economy_account(&guild_text, &command.user.id.to_string())?;
                let currency = setting_string(&self.store, &guild_text, "community.economy.currency_name")
                    .unwrap_or_else(|| "credits".to_string());
                format!("Your balance is **{}** {currency}.", account.balance)
            }
            "daily" => {
                let Some(guild_id) = command.guild_id else {
                    return respond(ctx, command, "This command can only be used in a server.").await;
                };
                let guild_text = guild_id.to_string();
                if !feature_enabled(&self.store, &guild_text, "community.economy", None) {
                    return respond(ctx, command, "Economy is disabled in this server. Enable it in the dashboard.").await;
                }
                let account = self.store.economy_account(&guild_text, &command.user.id.to_string())?;
                let economy_config = economy_config_for_store(&self.store, &guild_text);
                let decision = evaluate_economy(&economy_config, "daily", account.balance, true);
                if !decision.allowed {
                    return respond(ctx, command, &decision.explanation).await;
                }
                let reward = decision.amount;
                let currency = setting_string(&self.store, &guild_text, "community.economy.currency_name")
                    .unwrap_or_else(|| "credits".to_string());
                match self.store.claim_daily(&guild_text, &command.user.id.to_string(), reward)? {
                    Some(account) => format!("Daily reward claimed: **{}** {currency}. Your balance is **{}**.", reward, account.balance),
                    None => "You already claimed your daily reward. Try again after the 24-hour cooldown.".to_string(),
                }
            }
            "work" => {
                let Some(guild_id) = command.guild_id else {
                    return respond(ctx, command, "This command can only be used in a server.").await;
                };
                let guild_text = guild_id.to_string();
                if !feature_enabled(&self.store, &guild_text, "community.economy", None) {
                    return respond(ctx, command, "Economy is disabled in this server. Enable it in the dashboard.").await;
                }
                let account = self.store.economy_account(&guild_text, &command.user.id.to_string())?;
                let economy_config = economy_config_for_store(&self.store, &guild_text);
                let decision = evaluate_economy(&economy_config, "work", account.balance, true);
                if !decision.allowed {
                    return respond(ctx, command, &decision.explanation).await;
                }
                let reward = decision.amount;
                let cooldown = decision.cooldown_ms as u64;
                let currency = setting_string(&self.store, &guild_text, "community.economy.currency_name")
                    .unwrap_or_else(|| "credits".to_string());
                match self.store.claim_economy_reward(&guild_text, &command.user.id.to_string(), "work", reward, cooldown as i64)? {
                    Some(account) => format!("Work reward claimed: **{}** {currency}. Your balance is **{}**.", reward, account.balance),
                    None => format!("You are on cooldown. Try work again in about {}.", format_duration(cooldown as i64)),
                }
            }
            "economy-top" => {
                let Some(guild_id) = command.guild_id else {
                    return respond(ctx, command, "This command can only be used in a server.").await;
                };
                let guild_text = guild_id.to_string();
                if !feature_enabled(&self.store, &guild_text, "community.economy", None) {
                    return respond(ctx, command, "Economy is disabled in this server. Enable it in the dashboard.").await;
                }
                let currency = setting_string(&self.store, &guild_text, "community.economy.currency_name")
                    .unwrap_or_else(|| "credits".to_string());
                let rows = self.store.economy_top(&guild_text, 10)?;
                if rows.is_empty() {
                    "No community balances have been earned yet.".to_string()
                } else {
                    /*
                    rows.into_iter().enumerate().map(|(index, (user_id, balance))| {
                        format!("**{}\.** <@{}> — **{}** {}", index + 1, user_id, balance, currency)
                    }).collect::<Vec<_>>().join("\n")
                    */
                    rows.into_iter().enumerate().map(|(index, (user_id, balance))| {
                        format!("**{}.** <@{}> - **{}** {}", index + 1, user_id, balance, currency)
                    }).collect::<Vec<_>>().join("\n")
                }
            }
            "temp-channel" => {
                let Some(guild_id) = command.guild_id else {
                    return respond(ctx, command, "This command can only be used in a server.").await;
                };
                let guild_text = guild_id.to_string();
                if !feature_enabled(&self.store, &guild_text, "utility.temp_channels", None) {
                    return respond(ctx, command, "Temporary channels are disabled in this server. Enable them in the dashboard.").await;
                }
                let max_active = setting_u64(
                    &self.store,
                    &guild_text,
                    "utility.temp_channels.max_active",
                    10,
                )
                .clamp(1, 50) as i64;
                let active = self.store.active_temp_channels(&guild_text)?;
                let template = setting_string(
                    &self.store,
                    &guild_text,
                    "utility.temp_channels.name_template",
                )
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| "{user}'s room".to_string());
                let decision = evaluate_temp_channel(
                    &template,
                    command.user.name.as_str(),
                    active.max(0) as u64,
                    max_active as u64,
                );
                if !decision.allowed {
                    return respond(
                        ctx,
                        command,
                        "This server has reached its temporary room limit. Try again after one is cleaned up.",
                    )
                    .await;
                }
                let category_id = setting_string(
                    &self.store,
                    &guild_text,
                    "utility.temp_channels.category_id",
                )
                .and_then(|value| value.parse::<u64>().ok())
                .map(serenity::all::ChannelId::new);
                let mut create = CreateChannel::new(decision.room_name)
                    .kind(serenity::all::ChannelType::Voice);
                if let Some(category_id) = category_id {
                    create = create.category(category_id);
                }
                let channel = guild_id
                    .create_channel(&ctx.http, create)
                    .await?;
                self.store.register_temp_channel(
                    &guild_text,
                    &channel.id.to_string(),
                    &command.user.id.to_string(),
                )?;
                format!("Temporary voice channel created: <#{}>. It will be removed when everyone leaves.", channel.id)
            }
            "starboard-set" => {
                let Some(guild_id) = command.guild_id else {
                    return respond(ctx, command, "Este comando só pode ser usado num servidor.").await;
                };
                let Some(channel_id) = command.data.options.iter().find_map(|option| match option.value {
                    CommandDataOptionValue::Channel(channel) if option.name == "channel" => Some(channel),
                    _ => None,
                }) else {
                    return respond(ctx, command, "Indica um canal válido.").await;
                };
                let guild_text = guild_id.to_string();
                self.store.set_setting(&guild_text, "community.starboard.channel_id", &channel_id.to_string())?;
                let threshold = setting_i64(&self.store, &guild_text, "community.starboard.threshold", 3).clamp(1, 100);
                format!("Starboard configured in <#{}>. It requires {} stars to publish.", channel_id, threshold)
            }
            "suggest" => {
                let Some(guild_id) = command.guild_id else {
                    return respond(ctx, command, "Este comando só pode ser usado num servidor.").await;
                };
                if !feature_enabled(&self.store, &guild_id.to_string(), "community.suggestions", None) {
                    return respond(ctx, command, "As sugestões estão desativadas neste servidor. Ativa-as no painel.").await;
                }
                let text = option_string(command, "text").unwrap_or_default().trim();
                let guild_text = guild_id.to_string();
                let suggestion_config = serde_json::json!({
                    "channel": setting_string(&self.store, &guild_text, "community.suggestions.channel_id").unwrap_or_default(),
                    "anonymous": setting_bool(&self.store, &guild_text, "community.suggestions.anonymous", false),
                    "voteMode": setting_string(&self.store, &guild_text, "community.suggestions.vote_mode").unwrap_or_else(|| "up_down".into()),
                    "staffChannel": setting_string(&self.store, &guild_text, "community.suggestions.staff_channel_id").unwrap_or_default(),
                });
                let decision = evaluate_suggestion(
                    &suggestion_config,
                    text,
                    &command.channel_id.to_string(),
                );
                if !decision.allowed {
                    return respond(ctx, command, &decision.explanation).await;
                }
                let text = decision.text;
                let anonymous = decision.anonymous;
                let vote_mode = decision.vote_mode;
                let target_channel_id = decision.channel_id;
                let staff_channel_id = decision.staff_channel_id;
                let cooldown_hours = setting_i64(
                    &self.store,
                    &guild_text,
                    "community.suggestions.cooldown_hours",
                    24,
                )
                .clamp(0, 720);
                if cooldown_hours > 0
                    && let Some(created_at) = self.store.latest_suggestion_created_at(
                        &guild_text,
                        &command.user.id.to_string(),
                    )?
                {
                    let elapsed = Utc::now().timestamp_millis() - created_at;
                    let cooldown_ms = cooldown_hours.saturating_mul(60 * 60 * 1_000);
                    if elapsed < cooldown_ms {
                        let minutes = ((cooldown_ms - elapsed) / 60_000).max(1);
                        return respond(
                            ctx,
                            command,
                            &format!("You can submit another suggestion in about {minutes} minute(s)."),
                        )
                        .await;
                    }
                }
                if let Some(raw_role) = setting_string(&self.store, &guild_text, "community.suggestions.required_role")
                    .filter(|value| !value.trim().is_empty())
                    && let Ok(role_id) = raw_role.parse::<u64>()
                {
                    let member = guild_id.member(&ctx.http, command.user.id).await?;
                    if !member.roles.iter().any(|role| role.get() == role_id) {
                        return respond(ctx, command, "You need the configured role to submit a suggestion.").await;
                    }
                }
                let author = if anonymous {
                    "Anonymous".to_string()
                } else {
                    format!("<@{}>", command.user.id)
                };
                let target_channel = target_channel_id
                    .parse::<u64>()
                    .map(ChannelId::new)
                    .unwrap_or(command.channel_id);
                // The database ID is needed in the public panel. If publishing
                // fails, remove the draft so it cannot trigger a false cooldown.
                let id = self.store.create_suggestion_in_channel(
                    &guild_text,
                    &command.user.id.to_string(),
                    &text,
                    Some(&target_channel.to_string()),
                )?;
                let public_content = render_suggestion_message(id, &author, &text, "pending", 0, 0);
                if !suggestion_message_fits(&public_content) {
                    self.store.delete_unpublished_suggestion(&guild_text, id)?;
                    return respond(ctx, command, "Suggestion is too long for a Discord message.").await;
                }
                let published = suggestion_display::publish(ctx, target_channel, None,
                    &suggestion_display::Content { id, author: &author, text: &text, status: "pending", up: 0, down: 0 },
                    (!anonymous).then_some(&command.user), vote_mode != "up_only").await;
                let message = match published {
                    Ok(message) => message,
                    Err(_) => {
                        self.store.delete_unpublished_suggestion(&guild_text, id)?;
                        return respond(ctx, command, "Could not publish the suggestion in the configured channel.").await;
                    }
                };
                if let Err(error) = self.store.set_suggestion_message(id, &message.id.to_string()) {
                    let _ = target_channel.delete_message(&ctx.http, message.id).await;
                    let _ = self.store.delete_unpublished_suggestion(&guild_text, id);
                    return Err(error);
                }
                if let Some(staff_channel) = staff_channel_id.and_then(|value| value.parse::<u64>().ok())
                {
                    let _ = ChannelId::new(staff_channel)
                        .send_message(
                            &ctx.http,
                            CreateMessage::new()
                                .content(format!(
                                    "New suggestion #{id} submitted by <@{}>: {text}",
                                    command.user.id
                                ))
                                .allowed_mentions(
                                    CreateAllowedMentions::new()
                                        .everyone(false)
                                        .empty_users()
                                        .empty_roles()
                                        .replied_user(false),
                                ),
                        )
                        .await;
                }
                format!("Suggestion #{id} published.")
            }
            "suggestion" => {
                let Some(guild_id) = command.guild_id else {
                    return respond(ctx, command, "Este comando só pode ser usado num servidor.").await;
                };
                if !feature_enabled(&self.store, &guild_id.to_string(), "community.suggestions", None) {
                    return respond(ctx, command, "As sugestões estão desativadas neste servidor. Ativa-as no painel.").await;
                }
                let id = option_i64(command, "id").unwrap_or(0);
                let status = option_string(command, "status").unwrap_or_default().to_ascii_lowercase();
                if !matches!(status.as_str(), "pending" | "approved" | "denied" | "considered") {
                    return respond(ctx, command, "Estado inválido: pending, approved, denied ou considered.").await;
                }
                let guild_text = guild_id.to_string();
                let update_lock = suggestion_display::update_lock(id);
                let _update = update_lock.lock().await;
                let Some(suggestion) = self.store.suggestion(id)? else {
                    return respond(ctx, command, "Suggestion not found in this server.").await;
                };
                if suggestion.guild_id != guild_text {
                    return respond(ctx, command, "Suggestion not found in this server.").await;
                }
                self.store.set_suggestion_status(&guild_text, id, &status)?;
                let channel_id = suggestion.channel_id
                    .clone()
                    .or_else(|| setting_string(&self.store, &guild_text, "community.suggestions.channel_id"))
                    .and_then(|value| value.parse::<u64>().ok());
                if let (Some(channel_id), Some(message_id)) = (
                    channel_id,
                    suggestion.message_id.as_deref().and_then(|value| value.parse::<u64>().ok()),
                ) {
                    let panel_channel = ChannelId::new(channel_id);
                    if let Ok(panel) = panel_channel.message(&ctx.http, MessageId::new(message_id)).await {
                        let author = suggestion_display::published_author(id, &suggestion.author_id, &panel);
                        let (up, down) = self.store.suggestion_votes(id)?;
                        let content = render_suggestion_message(id, &author, &suggestion.content, &status, up, down);
                        let user = if author != "Anonymous" {
                            suggestion.author_id.parse::<u64>().ok().map(serenity::all::UserId::new)
                        } else { None };
                        let user = if let Some(user) = user { user.to_user(&ctx.http).await.ok() } else { None };
                        let against = setting_string(&self.store, &guild_text, "community.suggestions.vote_mode").as_deref() != Some("up_only");
                        if suggestion_message_fits(&content)
                            && suggestion_display::publish(ctx, panel_channel, Some(MessageId::new(message_id)),
                                &suggestion_display::Content { id, author: &author, text: &suggestion.content, status: &status, up, down },
                                user.as_ref(), against)
                                .await.is_ok()
                        {
                            format!("Suggestion #{id} marked as {status}.")
                        } else {
                            format!("Suggestion #{id} marked as {status}, but the public panel could not be updated.")
                        }
                    } else {
                        format!("Suggestion #{id} marked as {status}, but the public panel could not be found.")
                    }
                } else {
                    format!("Suggestion #{id} marked as {status}, but this older panel has no saved channel to update.")
                }
            }
            "giveaway-start" | "gstart" => {
                let Some(guild_id) = command.guild_id else {
                    return respond(ctx, command, "Este comando só pode ser usado num servidor.").await;
                };
                if !feature_enabled(&self.store, &guild_id.to_string(), "community.giveaways", None) {
                    return respond(ctx, command, "Os giveaways estão desativados neste servidor. Ativa-os no painel.").await;
                }
                let prize = option_string(command, "prize").unwrap_or_default().trim();
                let default_hours = setting_u64(&self.store, &guild_id.to_string(), "community.giveaways.default_duration_hours", 24).clamp(1, 168);
                let duration = option_string(command, "duration").unwrap_or_default();
                let Some(delay) = (if duration.trim().is_empty() {
                    Some((default_hours as i64) * 3_600_000)
                } else {
                    parse_duration(duration)
                }) else {
                    return respond(ctx, command, "Duração inválida. Usa 10m, 2h ou 1d.").await;
                };
                if prize.is_empty() || prize.chars().count() > 200 {
                    return respond(ctx, command, "O prémio deve ter entre 1 e 200 caracteres.").await;
                }
                let winners = option_i64(command, "winners").unwrap_or_else(|| setting_u64(&self.store, &guild_id.to_string(), "community.giveaways.default_winners", 1) as i64).clamp(1, 20);
                let required_role = command.data.options.iter().find_map(|option| match option.value {
                    CommandDataOptionValue::Role(role) if option.name == "required_role" => Some(role.to_string()),
                    _ => None,
                }).or_else(|| setting_string(&self.store, &guild_id.to_string(), "community.giveaways.required_role").filter(|value| !value.trim().is_empty()));
                let giveaway_config = serde_json::json!({
                    "defaultDurationHours": default_hours,
                    "defaultWinners": setting_u64(&self.store, &guild_id.to_string(), "community.giveaways.default_winners", 1),
                    "requiredRole": required_role.clone().unwrap_or_default(),
                });
                let decision = evaluate_giveaway(
                    &giveaway_config,
                    prize,
                    Some(winners),
                    Some(delay),
                    required_role.as_deref(),
                );
                if !decision.allowed {
                    return respond(ctx, command, &decision.explanation).await;
                }
                let prize = decision.prize;
                let winners = decision.winners as i64;
                let required_role = decision.required_role_id;
                let end_at = chrono::Utc::now().timestamp_millis() + decision.duration_ms;
                let guild_text = guild_id.to_string();
                let id = self.store.create_scheduled_giveaway(&guild_text, &command.channel_id.to_string(), &prize, winners, end_at, required_role.as_deref(), &command.user.id.to_string())?;
                let giveaway = self.store.giveaway(id)?.ok_or_else(|| anyhow::anyhow!("new giveaway record is missing"))?;
                let published = giveaway_display::publish(&ctx.http, command.channel_id, None,
                    &giveaway_display::Content {giveaway: &giveaway, winners: None, rerolled: false, participants: 0}, false).await;
                let message = match published {
                    Ok(message) => message,
                    Err(error) => {
                        self.store.delete_unpublished_giveaway(&guild_text, id)?;
                        warn!(%guild_text, giveaway_id = id, %error, "could not publish giveaway panel");
                        return respond(ctx, command, "Could not publish the giveaway in this channel.").await;
                    }
                };
                if let Err(error) = self.store.set_giveaway_message(id, &message.id.to_string()) {
                    let _ = command.channel_id.delete_message(&ctx.http, message.id).await;
                    let _ = self.store.delete_unpublished_giveaway(&guild_text, id);
                    return Err(error);
                }
                format!("Giveaway #{id} created.")
            }
            "giveaway-end" | "gend" => {
                let Some(guild_id) = command.guild_id else {
                    return respond(ctx, command, "This command can only be used in a server.").await;
                };
                let id = option_i64(command, "id").unwrap_or(0);
                if finish_giveaway(&ctx.http, &self.store, &guild_id.to_string(), id).await? {
                    format!("Giveaway #{id} ended.")
                } else {
                    "Giveaway not found or already ended.".to_string()
                }
            }
            "giveaway-list" | "glist" => {
                let Some(guild_id) = command.guild_id else {
                    return respond(ctx, command, "Este comando só pode ser usado num servidor.").await;
                };
                if !feature_enabled(&self.store, &guild_id.to_string(), "community.giveaways", None) {
                    return respond(ctx, command, "Os giveaways estão desativados neste servidor. Ativa-os no painel.").await;
                }
                let rows = self.store.active_giveaways(&guild_id.to_string(), 20)?;
                if rows.is_empty() { "There are no active giveaways.".to_string() } else {
                    rows.into_iter().map(|row| format!("#{} — {} — ends <t:{}:R>", row.id, row.prize, row.end_at / 1_000)).collect::<Vec<_>>().join("\n")
                }
            }
            "greroll" => {
                let Some(guild_id) = command.guild_id else {
                    return respond(ctx, command, "This command can only be used in a server.").await;
                };
                let id = option_i64(command, "id").unwrap_or(0);
                match reroll_giveaway(&ctx.http, &self.store, &guild_id.to_string(), id).await? {
                    Some(winner) => format!("Giveaway #{id} rerolled: <@{winner}>."),
                    None => "Giveaway not found, still active or without participants.".to_string(),
                }
            }
            "poll" => {
                let Some(guild_id) = command.guild_id else {
                    return respond(ctx, command, "Este comando só pode ser usado num servidor.").await;
                };
                if !feature_enabled(&self.store, &guild_id.to_string(), "management.polls", None) {
                    return respond(ctx, command, "As enquetes estão desativadas neste servidor. Ativa-as no painel.").await;
                }
                let question = option_string(command, "question").unwrap_or_default().trim();
                let mut options = Vec::new();
                for name in ["option1", "option2", "option3", "option4", "option5"] {
                    if let Some(value) = option_string(command, name).map(str::trim).filter(|value| !value.is_empty()) {
                        options.push(value.to_string());
                    }
                }
                if question.is_empty() || options.len() < 2 {
                    return respond(ctx, command, "Indica uma pergunta e pelo menos duas opções.").await;
                }
                let poll_duration = option_string(command, "duration").unwrap_or_default();
                let default_hours = setting_u64(&self.store, &guild_id.to_string(), "management.polls.default_duration_hours", 24).clamp(1, 168);
                let configured_channel = setting_string(&self.store, &guild_id.to_string(), "management.polls.channel_id")
                    .filter(|value| !value.trim().is_empty());
                let poll_config = serde_json::json!({
                    "defaultDurationHours": default_hours,
                    "channel": configured_channel.clone().unwrap_or_default(),
                });
                let duration_override_ms = if poll_duration.trim().is_empty() {
                    None
                } else {
                    let Some(duration) = parse_duration(poll_duration) else {
                        return respond(ctx, command, "Invalid duration. Use a value such as 10m, 2h or 1d.").await;
                    };
                    Some(duration)
                };
                let decision = evaluate_poll(
                    &poll_config,
                    question,
                    &options,
                    duration_override_ms,
                    &command.channel_id.to_string(),
                );
                if !decision.allowed {
                    return respond(ctx, command, &decision.explanation).await;
                }
                let question = decision.question;
                let options = decision.options;
                let delay = decision.duration_ms;
                let end_at = chrono::Utc::now().timestamp_millis() + delay;
                let poll_channel = decision.channel_id;
                let guild_text = guild_id.to_string();
                let id = self.store.create_scheduled_poll(&guild_text, &poll_channel, &question, &options, end_at)?;
                let message_channel = poll_channel.parse::<u64>().map(ChannelId::new).unwrap_or(command.channel_id);
                let published = message_channel.send_message(&ctx.http, poll_open_message(id, &question, &options, end_at)).await;
                let message = match published {
                    Ok(message) => message,
                    Err(error) => {
                        self.store.delete_unpublished_poll(&guild_text, id)?;
                        warn!(%guild_text, poll_id = id, %error, "could not publish poll panel");
                        return respond(ctx, command, "Could not publish the poll in this channel.").await;
                    }
                };
                if let Err(error) = self.store.set_poll_message(id, &message.id.to_string()) {
                    let _ = message_channel.delete_message(&ctx.http, message.id).await;
                    let _ = self.store.delete_unpublished_poll(&guild_text, id);
                    return Err(error);
                }
                format!("Poll #{id} created.")
            }
            "quarantine" => {
                let Some(guild_id) = command.guild_id else {
                    return respond(ctx, command, "Este comando só pode ser usado num servidor.").await;
                };
                let Some(target) = command.data.options.iter().find_map(|option| match option.value {
                    CommandDataOptionValue::User(user) if option.name == "user" => Some(user),
                    _ => None,
                }) else {
                    return respond(ctx, command, "Indica um membro.").await;
                };
                let member = guild_id.member(&ctx.http, target).await?;
                let role_ids = member.roles.iter().map(|role| role.to_string()).collect::<Vec<_>>();
                let reason = option_string(command, "reason").unwrap_or("Quarantine manual");
                if !self.store.begin_quarantine(&guild_id.to_string(), &target.to_string(), &role_ids, reason)? {
                    return respond(ctx, command, "This member already has saved quarantine roles. Use /unquarantine to restore them first.").await;
                }
                let mut failed = 0;
                for role in &member.roles {
                    if let Err(error) = member.remove_role(&ctx.http, *role).await {
                        failed += 1;
                        warn!(%guild_id, %target, role_id = %role, %error, "could not remove quarantine role");
                    }
                }
                let case_id = self.store.record_case(&guild_id.to_string(), "quarantine", &target.to_string(), &command.user.id.to_string(), reason, None)?;
                if failed == 0 {
                    format!("<@{}> quarantined as case #{case_id}. Roles were saved for restoration.", target)
                } else {
                    format!("Quarantine incomplete for <@{target}> (case #{case_id}): could not remove {failed} role(s). Original roles are saved; check the bot's permissions and role hierarchy.")
                }
            }
            "unquarantine" => {
                let Some(guild_id) = command.guild_id else {
                    return respond(ctx, command, "Este comando só pode ser usado num servidor.").await;
                };
                let Some(target) = command.data.options.iter().find_map(|option| match option.value {
                    CommandDataOptionValue::User(user) if option.name == "user" => Some(user),
                    _ => None,
                }) else {
                    return respond(ctx, command, "Indica um membro.").await;
                };
                let Some(record) = self.store.get_quarantine(&guild_id.to_string(), &target.to_string())? else {
                    return respond(ctx, command, "Esse membro não está em quarantine.").await;
                };
                let member = guild_id.member(&ctx.http, target).await?;
                let role_member = &member;
                let role_http = &ctx.http;
                let (restored, pending) = restore_quarantine_roles(
                    &self.store, &guild_id.to_string(), &target.to_string(), &record.role_ids, &record.reason,
                    |role| async move { role_member.add_role(role_http, role).await.is_ok() },
                ).await?;
                if pending == 0 {
                    format!("Quarantine removed from <@{}>; {} role(s) restored.", target, restored)
                } else {
                    format!("Quarantine partially restored for <@{target}>: {restored} role(s) restored, {pending} still pending. Pending roles are saved; check permissions and retry /unquarantine.")
                }
            }
            "join-gate" => {
                let Some(guild_id) = command.guild_id else {
                    return respond(ctx, command, "Este comando só pode ser usado num servidor.").await;
                };
                let enabled = option_bool(command, "enabled").unwrap_or(false);
                let minimum_age = option_i64(command, "min_age_days").unwrap_or(0).clamp(0, 365);
                self.store.set_setting(
                    &guild_id.to_string(),
                    "security.join_gate.enabled",
                    if enabled { "true" } else { "false" },
                )?;
                self.store.set_setting(
                    &guild_id.to_string(),
                    "security.join_gate.min_age_days",
                    &minimum_age.to_string(),
                )?;
                if let Some(role_id) = command.data.options.iter().find_map(|option| {
                    (option.name == "role").then_some(match option.value {
                        CommandDataOptionValue::Role(role) => role,
                        _ => return None,
                    })
                }) {
                    self.store.set_setting(
                        &guild_id.to_string(),
                        "security.join_gate.role_id",
                        &role_id.to_string(),
                    )?;
                }
                if enabled {
                    let role_note = if option_role(command, "role").is_some() {
                        "; verification role updated"
                    } else {
                        "; configure a role to restrict channels"
                    };
                    format!("Join gate enabled for accounts younger than {minimum_age} day(s){role_note}.")
                } else {
                    "Join gate disabled; saved settings can be re-enabled.".to_string()
                }
            }
            "verify-panel" => {
                let Some(guild_id) = command.guild_id else {
                    return respond(ctx, command, "Este comando só pode ser usado num servidor.").await;
                };
                let guild_text = guild_id.to_string();
                let enabled = self.store.get_setting(&guild_text, "security.join_gate.enabled")?
                    .is_some_and(|value| value == "true");
                let Some(verified_role_id) = setting_u64_optional(
                    &self.store,
                    &guild_text,
                    "security.join_gate.auto_role_id",
                ) else {
                    return respond(ctx, command, "Configure a verified-member role in Join Gate before posting a verification panel.").await;
                };
                if !enabled {
                    return respond(ctx, command, "Ativa primeiro o `/join-gate`; o painel não deve ficar exposto enquanto o gate está desligado.").await;
                }
                command.channel_id.send_message(
                    &ctx.http,
                    serenity::all::CreateMessage::new()
                        .content("Click the button to receive the verified member role.")
                        .components(vec![CreateActionRow::Buttons(vec![
                            CreateButton::new(format!("verify:{guild_text}:{verified_role_id}"))
                                .label("Verify")
                                .style(ButtonStyle::Success),
                        ])]),
                ).await?;
                "Verification panel posted in this channel.".to_string()
            }
            "lockdown" => {
                let Some(guild_id) = command.guild_id else {
                    return respond(ctx, command, "Este comando só pode ser usado num servidor.").await;
                };
                let reason = option_string(command, "reason").unwrap_or("Lockdown manual");
                let count = apply_lockdown(&ctx.http, &self.store, guild_id, true).await?;
                self.store.set_setting(&guild_id.to_string(), "security.lockdown.reason", reason)?;
                format!("Lockdown applied to {count} text channel(s). Reason: {reason}.")
            }
            "unlock" => {
                let Some(guild_id) = command.guild_id else {
                    return respond(ctx, command, "Este comando só pode ser usado num servidor.").await;
                };
                let count = apply_lockdown(&ctx.http, &self.store, guild_id, false).await?;
                format!("Lockdown removed from {count} channel(s); previous overwrites were restored when saved.")
            }
            "security-mode" => {
                let Some(guild_id) = command.guild_id else {
                    return respond(ctx, command, "Este comando só pode ser usado num servidor.").await;
                };
                let shadow = option_bool(command, "shadow").unwrap_or(false);
                self.store.set_setting(
                    &guild_id.to_string(),
                    "security.shadow_mode",
                    if shadow { "true" } else { "false" },
                )?;
                if shadow {
                    "Shadow mode enabled: anti-raid/anti-nuke responses are monitored with cases and alerts, without automatic containment.".to_string()
                } else {
                    "Shadow mode disabled: configured security responses may apply limited containment.".to_string()
                }
            }
            "anti-raid" => {
                let Some(guild_id) = command.guild_id else {
                    return respond(ctx, command, "Este comando só pode ser usado num servidor.").await;
                };
                let enabled = option_bool(command, "enabled").unwrap_or(false);
                let joins = option_i64(command, "joins").unwrap_or(10).clamp(2, 100);
                let window_seconds = option_i64(command, "window_seconds").unwrap_or(10).clamp(3, 60);
                let guild_text = guild_id.to_string();
                self.store.set_setting(
                    &guild_text,
                    "security.anti_raid.enabled",
                    if enabled { "true" } else { "false" },
                )?;
                self.store.set_setting(
                    &guild_text,
                    "security.anti_raid.joins",
                    &joins.to_string(),
                )?;
                self.store.set_setting(
                    &guild_text,
                    "security.anti_raid.window_seconds",
                    &window_seconds.to_string(),
                )?;
                if enabled {
                    format!("Anti-raid enabled: {joins} joins in {window_seconds}s enable the join gate.")
                } else {
                    "Anti-raid disabled; no automatic response to join bursts will be applied.".to_string()
                }
            }
            "anti-nuke" => {
                let Some(guild_id) = command.guild_id else {
                    return respond(ctx, command, "Este comando só pode ser usado num servidor.").await;
                };
                let enabled = option_bool(command, "enabled").unwrap_or(false);
                let actions = option_i64(command, "actions").unwrap_or(3).clamp(2, 25);
                let window_seconds = option_i64(command, "window_seconds").unwrap_or(10).clamp(3, 60);
                let incident_minutes = option_i64(command, "incident_minutes")
                    .unwrap_or(10)
                    .clamp(1, 120);
                let guild_text = guild_id.to_string();
                self.store.set_setting(
                    &guild_text,
                    "security.anti_nuke.enabled",
                    if enabled { "true" } else { "false" },
                )?;
                self.store.set_setting(
                    &guild_text,
                    "security.anti_nuke.actions",
                    &actions.to_string(),
                )?;
                self.store.set_setting(
                    &guild_text,
                    "security.anti_nuke.window_seconds",
                    &window_seconds.to_string(),
                )?;
                self.store.set_setting(
                    &guild_text,
                    "security.anti_nuke.incident_minutes",
                    &incident_minutes.to_string(),
                )?;
                self.store.set_setting(
                    &guild_text,
                    "feature.management.audit",
                    if enabled { "true" } else { "false" },
                )?;
                if enabled {
                    format!("Anti-nuke enabled: {actions} destructive actions in {window_seconds}s trigger temporary containment for {incident_minutes} minutes and an alert.")
                } else {
                    "Anti-nuke disabled; Audit Log events do not trigger automatic containment.".to_string()
                }
            }
            "event-create" => {
                let Some(guild_id) = command.guild_id else {
                    return respond(ctx, command, "Este comando só pode ser usado num servidor.").await;
                };
                if !feature_enabled(&self.store, &guild_id.to_string(), "community.events", None) {
                    return respond(ctx, command, "Os eventos estão desativados neste servidor. Ativa-os no painel.").await;
                }
                let name = option_string(command, "name").unwrap_or_default().trim();
                let start_raw = option_string(command, "start").unwrap_or_default().trim();
                let end_raw = option_string(command, "end").map(|value| value.trim().to_owned());
                let location = option_string(command, "location").unwrap_or_default().trim();
                let description = option_string(command, "description").unwrap_or_default().trim();
                let default_capacity = setting_u64(&self.store, &guild_id.to_string(), "community.events.default_capacity", 0).min(100_000) as i64;
                let capacity = option_i64(command, "capacity").or((default_capacity > 0).then_some(default_capacity));
                if let Some(capacity) = capacity
                    && !(1..=100_000).contains(&capacity)
                {
                    return respond(ctx, command, "A lotação deve estar entre 1 e 100000.").await;
                }
                if !(1..=100).contains(&name.len())
                    || !(1..=100).contains(&location.len())
                    || description.len() > 1_000
                {
                    return respond(ctx, command, "Nome, local ou descrição inválidos.").await;
                }
                let now_seconds = serenity::all::Timestamp::now().unix_timestamp();
                let (start, end) = if let Some(end_raw) = end_raw.as_deref() {
                    match parse_scheduled_event_window(start_raw, end_raw, now_seconds) {
                        Ok(window) => window,
                        Err(reason) => {
                            let message = match reason {
                                "invalid_start" => "The start date is not valid RFC3339.",
                                "invalid_end" => "The end date is not valid RFC3339.",
                                "start_must_be_in_future" => "The start must be in the future.",
                                "end_must_follow_start" => "The end must be after the start.",
                                "event_too_long" => "The event cannot last longer than 365 days.",
                                _ => "The event window is invalid.",
                            };
                            return respond(ctx, command, message).await;
                        }
                    }
                } else {
                    let start = match serenity::all::Timestamp::parse(start_raw) {
                        Ok(value) if value.unix_timestamp() > now_seconds => value,
                        Ok(_) => {
                            return respond(ctx, command, "The start must be in the future.").await;
                        }
                        Err(_) => {
                            return respond(ctx, command, "The start date is not valid RFC3339.").await;
                        }
                    };
                    let duration_hours = setting_u64(
                        &self.store,
                        &guild_id.to_string(),
                        "community.events.default_duration_hours",
                        2,
                    )
                    .clamp(1, 8_760);
                    let end_seconds = start
                        .unix_timestamp()
                        .checked_add((duration_hours as i64).saturating_mul(3_600))
                        .ok_or_else(|| anyhow::anyhow!("event duration overflowed"))?;
                    let end = serenity::all::Timestamp::from_unix_timestamp(end_seconds)
                        .map_err(|_| anyhow::anyhow!("event duration is invalid"))?;
                    (start, end)
                };
                let event_config = serde_json::json!({
                    "defaultCapacity": default_capacity,
                    "announcementChannel": setting_string(
                        &self.store,
                        &guild_id.to_string(),
                        "community.events.announcement_channel_id",
                    ).unwrap_or_default(),
                    "reminders": setting_bool(
                        &self.store,
                        &guild_id.to_string(),
                        "community.events.reminders",
                        true,
                    ),
                    "reminderHours": setting_u64(
                        &self.store,
                        &guild_id.to_string(),
                        "community.events.reminder_hours",
                        1,
                    ),
                });
                let decision = evaluate_event(
                    &event_config,
                    name,
                    location,
                    description,
                    start.unix_timestamp(),
                    end.unix_timestamp(),
                    capacity,
                    now_seconds,
                );
                if !decision.allowed {
                    return respond(ctx, command, &decision.explanation).await;
                }
                let mut builder = serenity::all::CreateScheduledEvent::new(
                    serenity::all::ScheduledEventType::External,
                    name.to_string(),
                    start,
                )
                .end_time(end)
                .location(location.to_string())
                .audit_log_reason("Vozen Helper event-create");
                if !description.is_empty() {
                    builder = builder.description(description.to_string());
                }
                let event = guild_id.create_scheduled_event(&ctx.http, builder).await?;
                if let Some(capacity) = capacity {
                    self.store.set_setting(
                        &guild_id.to_string(),
                        &format!("events.capacity.{}", event.id),
                        &capacity.to_string(),
                    )?;
                }
                if let Some(channel_id) = setting_string(&self.store, &guild_id.to_string(), "community.events.announcement_channel_id")
                    .and_then(|value| value.parse::<u64>().ok())
                {
                    let _ = ChannelId::new(channel_id).send_message(
                        &ctx.http,
                        CreateMessage::new().content(format!("New event **{}** is scheduled for <t:{}:F>.", event.name, start.unix_timestamp())),
                    ).await;
                }
                schedule_event_reminder(
                    &self.store,
                    &guild_id.to_string(),
                    &event.id.to_string(),
                    &event.name,
                    start,
                )?;
                format!(
                    "Native event #{} created: **{}** (<t:{}:F>–<t:{}:F>).",
                    event.id,
                    event.name,
                    start.unix_timestamp(),
                    end.unix_timestamp()
                )
            }
            "event-list" => {
                let Some(guild_id) = command.guild_id else {
                    return respond(ctx, command, "Este comando só pode ser usado num servidor.").await;
                };
                let events = guild_id.scheduled_events(&ctx.http, false).await?;
                if events.is_empty() {
                    "There are no scheduled events in this server.".to_string()
                } else {
                    events
                        .into_iter()
                        .take(25)
                        .map(|event| {
                            format!(
                                "#{} **{}** · {:?} · <t:{}:F>",
                                event.id,
                                event.name,
                                event.status,
                                event.start_time.unix_timestamp()
                            )
                        })
                        .collect::<Vec<_>>()
                        .join("\n")
                }
            }
            "event-edit" => {
                let Some(guild_id) = command.guild_id else {
                    return respond(ctx, command, "Este comando só pode ser usado num servidor.").await;
                };
                if !feature_enabled(&self.store, &guild_id.to_string(), "community.events", None) {
                    return respond(ctx, command, "Os eventos estão desativados neste servidor. Ativa-os no painel.").await;
                }
                let event_id = option_i64(command, "event_id").unwrap_or(0);
                if event_id <= 0 {
                    return respond(ctx, command, "Indica um ID de evento válido.").await;
                }
                let event_id = serenity::all::ScheduledEventId::new(event_id as u64);
                let events = guild_id.scheduled_events(&ctx.http, false).await?;
                let Some(existing) = events.into_iter().find(|event| event.id == event_id) else {
                    return respond(ctx, command, "Não encontrei esse evento neste servidor.").await;
                };
                if matches!(
                    existing.status,
                    serenity::all::ScheduledEventStatus::Completed
                        | serenity::all::ScheduledEventStatus::Canceled
                ) {
                    return respond(ctx, command, "Completed or cancelled events cannot be edited.").await;
                }

                let name = option_string(command, "name").map(str::trim);
                if let Some(name) = name
                    && !(1..=100).contains(&name.len())
                {
                    return respond(ctx, command, "O nome tem de ter entre 1 e 100 caracteres.").await;
                }

                let location = option_string(command, "location").map(str::trim);
                if let Some(location) = location
                    && (existing.kind != serenity::all::ScheduledEventType::External
                        || !(1..=100).contains(&location.len()))
                {
                    return respond(ctx, command, "Location can only be changed for external events and must be 1–100 characters.").await;
                }

                let description = option_string(command, "description").map(str::trim);
                if let Some(description) = description
                    && description.len() > 1_000
                {
                    return respond(ctx, command, "The description cannot exceed 1,000 characters.").await;
                }

                let start_raw = option_string(command, "start").map(str::trim);
                let end_raw = option_string(command, "end").map(str::trim);
                let (start, end) = if start_raw.is_some() || end_raw.is_some() {
                    let start = match start_raw {
                        Some(raw) => serenity::all::Timestamp::parse(raw)
                            .map_err(|_| anyhow::anyhow!("The new start date is not valid RFC3339."))?,
                        None => existing.start_time,
                    };
                    let end = match end_raw {
                        Some(raw) => serenity::all::Timestamp::parse(raw)
                            .map_err(|_| anyhow::anyhow!("The new end date is not valid RFC3339."))?,
                        None => existing.end_time.ok_or_else(|| {
                            anyhow::anyhow!("This event has no end date; provide `end` to edit it.")
                        })?,
                    };
                    if start_raw.is_some()
                        && start.unix_timestamp()
                            <= serenity::all::Timestamp::now().unix_timestamp()
                    {
                        return respond(ctx, command, "The new start date must be in the future.").await;
                    }
                    if end.unix_timestamp() <= start.unix_timestamp() {
                        return respond(ctx, command, "The end must be after the start.").await;
                    }
                    if end.unix_timestamp() - start.unix_timestamp() > 365 * 86_400 {
                        return respond(ctx, command, "The event cannot last longer than 365 days.").await;
                    }
                    (Some(start), Some(end))
                } else {
                    (None, None)
                };

                if name.is_none()
                    && start.is_none()
                    && end.is_none()
                    && location.is_none()
                    && description.is_none()
                {
                    return respond(ctx, command, "Indica pelo menos um campo para alterar.").await;
                }

                let mut builder = serenity::all::EditScheduledEvent::new()
                    .audit_log_reason("Vozen Helper event-edit");
                if let Some(name) = name {
                    builder = builder.name(name.to_string());
                }
                if let Some(start) = start {
                    builder = builder.start_time(start);
                }
                if let Some(end) = end {
                    builder = builder.end_time(end);
                }
                if let Some(location) = location {
                    builder = builder.location(location.to_string());
                }
                if let Some(description) = description {
                    builder = builder.description(description.to_string());
                }
                let edited = guild_id.edit_scheduled_event(&ctx.http, event_id, builder).await?;
                schedule_event_reminder(
                    &self.store,
                    &guild_id.to_string(),
                    &edited.id.to_string(),
                    &edited.name,
                    edited.start_time,
                )?;
                format!("Native event #{} updated: **{}**.", edited.id, edited.name)
            }
            "event-register" => {
                let Some(guild_id) = command.guild_id else {
                    return respond(ctx, command, "Este comando só pode ser usado num servidor.").await;
                };
                let raw_event_id = option_i64(command, "event_id").unwrap_or(0);
                if raw_event_id <= 0 {
                    return respond(ctx, command, "Indica um ID de evento válido.").await;
                }
                let event_id = serenity::all::ScheduledEventId::new(raw_event_id as u64);
                let events = guild_id.scheduled_events(&ctx.http, false).await?;
                let Some(event) = events.into_iter().find(|event| event.id == event_id) else {
                    return respond(ctx, command, "Não encontrei esse evento neste servidor.").await;
                };
                if matches!(
                    event.status,
                    serenity::all::ScheduledEventStatus::Completed
                        | serenity::all::ScheduledEventStatus::Canceled
                ) {
                    return respond(ctx, command, "Este evento já terminou ou foi cancelado.").await;
                }
                let guild_text = guild_id.to_string();
                let capacity = self
                    .store
                    .get_setting(&guild_text, &format!("events.capacity.{}", event_id))?
                    .and_then(|value| value.parse::<u64>().ok());
                let inserted = self
                    .store
                    .register_event_with_capacity(
                        &guild_text,
                        &event_id.to_string(),
                        &command.user.id.to_string(),
                        capacity,
                    )?
                    .is_some();
                if inserted {
                    let waitlisted = self
                        .store
                        .event_registration(
                            &guild_text,
                            &event_id.to_string(),
                            &command.user.id.to_string(),
                        )?
                        .is_some_and(|registration| registration.status == "waitlisted");
                    if waitlisted {
                        format!(
                            "Event **{}** is full; you were added to the waitlist.",
                            event.name
                        )
                    } else {
                        format!("Registration confirmed for **{}**.", event.name)
                    }
                } else {
                    "You are already registered for this event.".to_string()
                }
            }
            "event-unregister" => {
                let Some(guild_id) = command.guild_id else {
                    return respond(ctx, command, "Este comando só pode ser usado num servidor.").await;
                };
                let raw_event_id = option_i64(command, "event_id").unwrap_or(0);
                if raw_event_id <= 0 {
                    return respond(ctx, command, "Indica um ID de evento válido.").await;
                }
                let (removed, promoted) = self.store.remove_event_registration(
                    &guild_id.to_string(),
                    &raw_event_id.to_string(),
                    &command.user.id.to_string(),
                )?;
                if !removed {
                    return respond(ctx, command, "Não tens uma inscrição neste evento.").await;
                }
                match promoted {
                    Some(user_id) => format!(
                        "Registration removed; <@{}> was promoted from the waitlist.",
                        user_id
                    ),
                    None => "Registration removed from the event.".to_string(),
                }
            }
            "event-checkin" => {
                let Some(guild_id) = command.guild_id else {
                    return respond(ctx, command, "Este comando só pode ser usado num servidor.").await;
                };
                let raw_event_id = option_i64(command, "event_id").unwrap_or(0);
                if raw_event_id <= 0 {
                    return respond(ctx, command, "Indica um ID de evento válido.").await;
                }
                let event_id = serenity::all::ScheduledEventId::new(raw_event_id as u64);
                let events = guild_id.scheduled_events(&ctx.http, false).await?;
                let Some(event) = events.into_iter().find(|event| event.id == event_id) else {
                    return respond(ctx, command, "Não encontrei esse evento neste servidor.").await;
                };
                if matches!(
                    event.status,
                    serenity::all::ScheduledEventStatus::Completed
                        | serenity::all::ScheduledEventStatus::Canceled
                ) {
                    return respond(ctx, command, "Este evento já terminou ou foi cancelado.").await;
                }
                let user_id = command.user.id.to_string();
                let Some(registration) = self.store.event_registration(
                    &guild_id.to_string(),
                    &event_id.to_string(),
                    &user_id,
                )? else {
                    return respond(ctx, command, "Inscreve-te primeiro com `/event-register`.").await;
                };
                if registration.status == "checked_in" {
                    return respond(ctx, command, "O teu check-in já está registado.").await;
                }
                if self.store.check_in_event(&guild_id.to_string(), &event_id.to_string(), &user_id)? {
                    format!("Check-in recorded for **{}**.", event.name)
                } else {
                    "Não foi possível registar o check-in.".to_string()
                }
            }
            "event-attendees" => {
                let Some(guild_id) = command.guild_id else {
                    return respond(ctx, command, "Este comando só pode ser usado num servidor.").await;
                };
                let raw_event_id = option_i64(command, "event_id").unwrap_or(0);
                if raw_event_id <= 0 {
                    return respond(ctx, command, "Indica um ID de evento válido.").await;
                }
                let event_id = serenity::all::ScheduledEventId::new(raw_event_id as u64);
                let events = guild_id.scheduled_events(&ctx.http, false).await?;
                let Some(event) = events.into_iter().find(|event| event.id == event_id) else {
                    return respond(ctx, command, "Não encontrei esse evento neste servidor.").await;
                };
                let registrations = self.store.event_registrations(
                    &guild_id.to_string(),
                    &event_id.to_string(),
                    100,
                )?;
                if registrations.is_empty() {
                    format!("**{}** has no registrations yet.", event.name)
                } else {
                    let lines = registrations
                        .into_iter()
                        .take(25)
                        .map(|registration| {
                            format!(
                                "<@{}> · {}",
                                registration.user_id,
                                if registration.status == "checked_in" {
                                    "check-in"
                                } else {
                                    "registered"
                                }
                            )
                        })
                        .collect::<Vec<_>>();
                    format!("**{}** — {} registration(s)\n{}", event.name, lines.len(), lines.join("\n"))
                }
            }
            "event-cancel" => {
                let Some(guild_id) = command.guild_id else {
                    return respond(ctx, command, "Este comando só pode ser usado num servidor.").await;
                };
                if !feature_enabled(&self.store, &guild_id.to_string(), "community.events", None) {
                    return respond(ctx, command, "Os eventos estão desativados neste servidor. Ativa-os no painel.").await;
                }
                let event_id = option_i64(command, "event_id").unwrap_or(0);
                if event_id <= 0 {
                    return respond(ctx, command, "Indica um ID de evento válido.").await;
                }
                guild_id
                    .delete_scheduled_event(
                        &ctx.http,
                        serenity::all::ScheduledEventId::new(event_id as u64),
                    )
                    .await?;
                self.store.delete_scheduled_actions_for(
                    &guild_id.to_string(),
                    "event_reminder",
                    &event_id.to_string(),
                )?;
                format!("Native event #{} cancelled.", event_id)
            }
            "workflow-create" => {
                let guild_text = match command.guild_id {
                    Some(guild_id) => guild_id.to_string(),
                    None => return respond(ctx, command, "This command can only be used in a server.").await,
                };
                if !feature_enabled(&self.store, &guild_text, "management.workflows", None) {
                    return respond(
                        ctx,
                        command,
                        "Automations are disabled in this server. Enable them in the dashboard.",
                    )
                    .await;
                }
                let name = option_string(command, "name").unwrap_or_default().trim();
                let condition = option_string(command, "contains").unwrap_or_default().trim();
                let reply = option_string(command, "reply")
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(str::to_string);
                let emoji = option_string(command, "emoji")
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(str::to_string);
                let (action, payload) = match (reply, emoji) {
                    (Some(reply), None) => ("reply", reply),
                    (None, Some(emoji)) if is_valid_workflow_reaction(&emoji) => ("react", emoji),
                    (None, Some(_)) => {
                        return respond(
                            ctx,
                            command,
                            "The emoji must be one short Unicode emoji; custom emojis are not supported.",
                        )
                        .await;
                    }
                    _ => {
                        return respond(
                            ctx,
                            command,
                            "Choose either reply text or one Unicode emoji reaction.",
                        )
                        .await;
                    }
                };
                let max_reply_length = setting_u64(
                    &self.store,
                    &guild_text,
                    "management.workflows.max_reply_length",
                    1_000,
                )
                .clamp(1, 1_500) as usize;
                if !(1..=50).contains(&name.len())
                    || (action == "reply" && !(1..=max_reply_length).contains(&payload.len()))
                    || condition.len() > 200
                {
                    return respond(ctx, command, "Nome, condição ou resposta inválidos.").await;
                }
                let user_text = command.user.id.to_string();
                let plan = self.effective_plan(&user_text, Some(&guild_text)).await;
                let plan_limit = quota_limit(&plan, "workflows");
                let configured_limit = setting_u64(
                    &self.store,
                    &guild_text,
                    "management.workflows.max_workflows",
                    plan_limit,
                )
                .clamp(1, 100);
                let workflow_limit = plan_limit.min(configured_limit);
                let Some(id) = self.store.create_workflow_bounded(
                    &guild_text,
                    name,
                    "message",
                    condition,
                    action,
                    &payload,
                    workflow_limit,
                )? else {
                    return respond(
                        ctx,
                        command,
                        &format!(
                            "A quota de workflows deste plano foi atingida ({workflow_limit}). Consulta `/plan` para saber como aumentar a capacidade da guild."
                        ),
                    )
                    .await;
                };
                format!(
                    "Workflow #{id} created. It {} when a message matches the condition.",
                    if action == "react" { "reacts" } else { "replies" }
                )
            }
            "workflow-list" => {
                let Some(guild_id) = command.guild_id else {
                    return respond(ctx, command, "Este comando só pode ser usado num servidor.").await;
                };
                let workflows = self.store.workflows(&guild_id.to_string(), 25)?;
                if workflows.is_empty() { "There are no workflows configured.".to_string() } else {
                    workflows.into_iter().map(|workflow| format!("#{} **{}** · {} · {}", workflow.id, workflow.name, workflow.trigger, if workflow.enabled { "enabled" } else { "disabled" })).collect::<Vec<_>>().join("\n")
                }
            }
            "workflow-dry-run" => {
                let Some(guild_id) = command.guild_id else {
                    return respond(ctx, command, "Este comando só pode ser usado num servidor.").await;
                };
                let id = option_i64(command, "id").unwrap_or(0);
                let sample = option_string(command, "message").unwrap_or_default().trim();
                if sample.len() > 2_000 {
                    return respond(ctx, command, "A mensagem de teste não pode exceder 2000 caracteres.").await;
                }
                let Some(workflow) = self.store.workflow(&guild_id.to_string(), id)? else {
                    return respond(ctx, command, "Workflow não encontrado neste servidor.").await;
                };
                let policy = WorkflowPolicy {
                    max_reply_length: setting_u64(
                        &self.store,
                        &guild_id.to_string(),
                        "management.workflows.max_reply_length",
                        1_000,
                    )
                    .clamp(1, 1_500) as usize,
                    allow_mentions: setting_bool(
                        &self.store,
                        &guild_id.to_string(),
                        "management.workflows.allow_mentions",
                        false,
                    ),
                };
                let decision = evaluate_workflow(
                    &policy,
                    &WorkflowObservation {
                        enabled: workflow.enabled,
                        trigger: workflow.trigger.clone(),
                        condition: workflow.condition.clone(),
                        action: workflow.action.clone(),
                        payload: workflow.payload.clone(),
                        message_content: sample.to_string(),
                        user_mention: format!("<@{}>", command.user.id),
                    },
                );
                if !decision.matched {
                    format!("Dry run: workflow **{}** would not run.", workflow.name)
                } else if let Some(reply) = decision.reply {
                    format!("Dry run: workflow **{}** would reply:\n> {}", workflow.name, reply)
                } else if let Some(reaction) = decision.reaction {
                    format!("Dry run: workflow **{}** would react with {}.", workflow.name, reaction)
                } else {
                    format!("Dry run: workflow **{}** would not run ({}).", workflow.name, decision.reason)
                }
            }
            "workflow-toggle" => {
                let Some(guild_id) = command.guild_id else {
                    return respond(ctx, command, "Este comando só pode ser usado num servidor.").await;
                };
                let id = option_i64(command, "id").unwrap_or(0);
                let enabled = option_bool(command, "enabled").unwrap_or(false);
                if self.store.set_workflow_enabled(&guild_id.to_string(), id, enabled)? {
                    format!("Workflow #{id} {}.", if enabled { "enabled" } else { "disabled immediately" })
                } else {
                    "Workflow not found in this server.".to_string()
                }
            }
            "workflow-delete" => {
                let Some(guild_id) = command.guild_id else {
                    return respond(ctx, command, "Este comando só pode ser usado num servidor.").await;
                };
                let id = option_i64(command, "id").unwrap_or(0);
                if self.store.delete_workflow(&guild_id.to_string(), id)? { format!("Workflow #{id} deleted.") } else { "Workflow not found in this server.".to_string() }
            }
            "ticket-config" => {
                let Some(guild_id) = command.guild_id else {
                    return respond(ctx, command, "Este comando só pode ser usado num servidor.").await;
                };
                let guild_text = guild_id.to_string();
                if let Some(role_id) = command.data.options.iter().find_map(|option| match option.value {
                    CommandDataOptionValue::Role(role) if option.name == "staff_role" => Some(role),
                    _ => None,
                }) {
                    self.store.set_setting(&guild_text, "support.ticket.staff_role_id", &role_id.to_string())?;
                }
                if let Some(channel_id) = command.data.options.iter().find_map(|option| match option.value {
                    CommandDataOptionValue::Channel(channel) if option.name == "transcript_channel" => Some(channel),
                    _ => None,
                }) {
                    self.store.set_setting(&guild_text, "support.ticket.transcript_channel_id", &channel_id.to_string())?;
                }
                if let Some(minutes) = option_i64(command, "sla_minutes") {
                    if !(5..=1_440).contains(&minutes) {
                        return respond(ctx, command, "O SLA deve estar entre 5 e 1440 minutos.").await;
                    }
                    self.store.set_setting(&guild_text, "support.ticket.sla_ms", &(minutes * 60_000).to_string())?;
                }
                "Ticket configuration saved.".to_string()
            }
            "ticket-panel" => {
                let Some(guild_id) = command.guild_id else {
                    return respond(ctx, command, "Este comando só pode ser usado num servidor.").await;
                };
                let guild_text = guild_id.to_string();
                let plan = self
                    .effective_plan(&command.user.id.to_string(), Some(&guild_text))
                    .await;
                let limit = quota_limit(&plan, "panels");
                let used = self
                    .store
                    .count_settings_prefix(&guild_text, "support.panel.")?;
                if used >= limit {
                    return respond(
                        ctx,
                        command,
                        "A quota de painéis de tickets deste servidor foi atingida.",
                    )
                    .await;
                }
                let title = setting_string(&self.store, &guild_text, "support.ticket.panel_title")
                    .filter(|value| !value.trim().is_empty())
                    .unwrap_or_else(|| "Need support?".to_string());
                let panel_channel = setting_string(&self.store, &guild_text, "support.ticket.panel_channel_id")
                    .and_then(|id| id.parse::<u64>().ok())
                    .filter(|id| *id > 0)
                    .map(serenity::all::ChannelId::new)
                    .unwrap_or(command.channel_id);
                if !matches!(panel_channel.to_channel(&ctx.http).await?, serenity::all::Channel::Guild(ref channel) if channel.guild_id == guild_id) {
                    return respond(ctx, command, "Choose a ticket panel channel in this server.").await;
                }
                let description = setting_string(
                    &self.store,
                    &guild_text,
                    "support.ticket.panel_description",
                )
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| {
                    "Open a private ticket and the support team will help you.".to_string()
                });
                let message = panel_channel
                    .send_message(
                        &ctx.http,
                        serenity::all::CreateMessage::new()
                            .content(format!("**{title}**\n{description}"))
                            .allowed_mentions(
                                CreateAllowedMentions::new()
                                    .everyone(false)
                                    .empty_users()
                                    .empty_roles(),
                            )
                            .components(vec![CreateActionRow::Buttons(vec![
                                CreateButton::new("ticket:open")
                                    .label("Open ticket")
                                    .style(ButtonStyle::Primary),
                            ])]),
                    )
                    .await?;
                self.store.set_setting(
                    &guild_text,
                    &format!("support.panel.{}", message.id),
                    &serde_json::json!({
                        "channel_id": panel_channel,
                        "message_id": message.id
                    })
                    .to_string(),
                )?;
                format!("Ticket panel created in <#{}>.", panel_channel)
            }
            "ticket-update" => {
                let Some(_guild_id) = command.guild_id else {
                    return respond(ctx, command, "Este comando só pode ser usado num servidor.").await;
                };
                let Some(ticket) = self.store.ticket_by_channel(&command.channel_id.to_string())? else {
                    return respond(ctx, command, "Este canal não é um ticket do Helper.").await;
                };
                let priority = option_string(command, "priority").map(str::trim);
                let category = option_string(command, "category").map(str::trim);
                let note = option_string(command, "note").map(str::trim);
                if priority.is_none() && category.is_none() && note.is_none() {
                    return respond(ctx, command, "Indica prioridade, categoria ou nota.").await;
                }
                if let Some(priority) = priority
                    && !matches!(priority, "low" | "normal" | "high" | "urgent")
                {
                    return respond(ctx, command, "Prioridade inválida.").await;
                }
                if let Some(category) = category
                    && !(1..=50).contains(&category.len())
                {
                    return respond(ctx, command, "The category must be between 1 and 50 characters.").await;
                }
                if let Some(note) = note
                    && note.len() > 2_000
                {
                    return respond(ctx, command, "The note cannot exceed 2,000 characters.").await;
                }
                if let Some(priority) = priority {
                    self.store.set_ticket_priority(&ticket.channel_id, priority)?;
                }
                if let Some(category) = category {
                    self.store.set_ticket_category(&ticket.channel_id, category)?;
                }
                if let Some(note) = note {
                    self.store.set_ticket_notes(&ticket.channel_id, note)?;
                }
                let updated = self.store.ticket_by_channel(&ticket.channel_id)?.ok_or_else(|| anyhow::anyhow!("ticket disappeared"))?;
                format!("Ticket updated: category **{}**, priority **{}**{}.", updated.category, updated.priority, if updated.notes.is_empty() { String::new() } else { " · internal note saved".to_string() })
            }
            "ticket-rate" => {
                let Some(_guild_id) = command.guild_id else {
                    return respond(ctx, command, "Este comando só pode ser usado num servidor.").await;
                };
                let Some(ticket) = self.store.ticket_by_channel(&command.channel_id.to_string())? else {
                    return respond(ctx, command, "Este canal não é um ticket do Helper.").await;
                };
                if ticket.user_id != command.user.id.to_string() {
                    return respond(ctx, command, "Só o autor do ticket pode avaliá-lo.").await;
                }
                let score = option_i64(command, "score").unwrap_or(0);
                if !(1..=5).contains(&score) {
                    return respond(ctx, command, "A avaliação tem de ser entre 1 e 5.").await;
                }
                if ticket.status != "closed" {
                    return respond(ctx, command, "Só podes avaliar um ticket fechado.").await;
                }
                if !self.store.set_ticket_csat(&ticket.channel_id, score)? {
                    return respond(ctx, command, "Não foi possível guardar a avaliação.").await;
                }
                format!("Thanks for the rating: **{score}/5**.")
            }
            "rolepanel" => {
                let Some(guild_id) = command.guild_id else {
                    return respond(ctx, command, "Este comando só pode ser usado num servidor.").await;
                };
                if !feature_enabled(&self.store, &guild_id.to_string(), "community.role_panels", None) {
                    return respond(ctx, command, "Os painéis de cargos estão desativados neste servidor. Ativa-os no painel.").await;
                }
                let guild_text = guild_id.to_string();
                let plan = self
                    .effective_plan(&command.user.id.to_string(), Some(&guild_text))
                    .await;
                let limit = quota_limit(&plan, "role_panels");
                let used = self
                    .store
                    .count_settings_prefix(&guild_text, "community.role_panel.")?;
                if used >= limit {
                    return respond(
                        ctx,
                        command,
                        "A quota de painéis de cargos deste servidor foi atingida.",
                    )
                    .await;
                }
                let title = option_string(command, "title")
                    .map(str::to_owned)
                    .or_else(|| setting_string(&self.store, &guild_text, "community.role_panels.title"))
                    .unwrap_or_else(|| "Choose your roles".to_string());
                let selection_mode = setting_string(
                    &self.store,
                    &guild_text,
                    "community.role_panels.selection_mode",
                )
                .filter(|mode| mode == "unique")
                .unwrap_or_else(|| "multiple".to_string());
                let guild_roles = guild_id.roles(&ctx.http).await?;
                let mut buttons = Vec::new();
                let mut role_ids = Vec::new();
                let max_roles = setting_u64(&self.store, &guild_text, "community.role_panels.max_roles", 5).clamp(1, 5) as usize;
                for name in ["role1", "role2", "role3", "role4", "role5"] {
                    if role_ids.len() >= max_roles { break; }
                    if let Some(role_id) = command.data.options.iter().find_map(|option| {
                        (option.name == name).then_some(match option.value {
                            CommandDataOptionValue::Role(role) => role,
                            _ => return None,
                        })
                    }) {
                        let role_name = guild_roles
                            .get(&role_id)
                            .map(|role| role.name.trim().chars().take(80).collect::<String>())
                            .filter(|name| !name.is_empty())
                            .unwrap_or_else(|| format!("Role {}", buttons.len() + 1));
                        role_ids.push(role_id.get());
                        buttons.push(
                            CreateButton::new(format!("role:toggle:{}", role_id.get()))
                                .label(role_name)
                                .style(ButtonStyle::Secondary),
                        );
                    }
                }
                if role_ids.is_empty() {
                    let configured_roles = setting_string(
                        &self.store,
                        &guild_text,
                        "community.role_panels.role_ids",
                    )
                    .unwrap_or_default();
                    for role_id in configured_roles
                        .split(',')
                        .map(str::trim)
                        .filter(|id| !id.is_empty())
                        .take(max_roles)
                    {
                        if let Ok(role_id) = role_id.parse::<u64>() {
                            let role_name = guild_roles
                                .get(&RoleId::new(role_id))
                                .map(|role| role.name.trim().chars().take(80).collect::<String>())
                                .filter(|name| !name.is_empty())
                                .unwrap_or_else(|| format!("Role {}", buttons.len() + 1));
                            role_ids.push(role_id);
                            buttons.push(
                                CreateButton::new(format!("role:toggle:{role_id}"))
                                    .label(role_name)
                                    .style(ButtonStyle::Secondary),
                            );
                        }
                    }
                }
                if buttons.is_empty() {
                    return respond(ctx, command, "Indica pelo menos um cargo válido.").await;
                }
                let panel_channel = setting_string(&self.store, &guild_text, "community.role_panels.channel_id")
                    .and_then(|value| value.parse::<u64>().ok())
                    .map(ChannelId::new)
                    .unwrap_or(command.channel_id);
                let description = setting_string(&self.store, &guild_text, "community.role_panels.description")
                    .filter(|value| !value.trim().is_empty());
                let message = panel_channel
                    .send_message(
                        &ctx.http,
                        serenity::all::CreateMessage::new()
                            .content(if let Some(description) = description { format!("{title}\n{description}") } else { title.clone() })
                            .components(vec![CreateActionRow::Buttons(buttons)]),
                    )
                    .await?;
                self.store.set_setting(
                    &guild_text,
                    &format!("community.role_panel.{}", message.id),
                    &serde_json::json!({
                        "channel_id": panel_channel,
                        "message_id": message.id,
                        "title": title,
                        "role_ids": role_ids,
                        "selection_mode": selection_mode,
                        "remove_on_unselect": setting_bool(
                            &self.store,
                            &guild_text,
                            "community.role_panels.remove_on_unselect",
                            true,
                        ),
                    })
                    .to_string(),
                )?;
                "Role panel created.".to_string()
            }
            _ => "Comando desconhecido.".to_string(),
        };
        respond(ctx, command, &content).await
    }

    async fn handle_component(
        &self,
        ctx: &Context,
        component: &serenity::all::ComponentInteraction,
    ) -> Result<()> {
        let Some(guild_id) = component.guild_id else {
            return respond_component(ctx, component, "Este botão só funciona num servidor.").await;
        };
        if let Some((kind, raw_id)) =
            component
                .data
                .custom_id
                .split_once(':')
                .and_then(|(prefix, rest)| {
                    let (action, id) = rest.split_once(':')?;
                    (prefix == "suggest" && (action == "up" || action == "down"))
                        .then_some((action, id))
                })
        {
            if !feature_enabled(
                &self.store,
                &guild_id.to_string(),
                "community.suggestions",
                None,
            ) {
                return respond_component(
                    ctx,
                    component,
                    "As sugestões estão desativadas neste servidor.",
                )
                .await;
            }
            let id = suggestion_display::vote_id(raw_id)
                .ok_or_else(|| anyhow::anyhow!("invalid suggestion button"))?;
            if kind == "down"
                && setting_string(
                    &self.store,
                    &guild_id.to_string(),
                    "community.suggestions.vote_mode",
                )
                .as_deref()
                    == Some("up_only")
            {
                return respond_component(
                    ctx,
                    component,
                    "This suggestion only accepts support votes.",
                )
                .await;
            }
            let update_lock = suggestion_display::update_lock(id);
            let _update = update_lock.lock().await;
            let Some(suggestion) = self.store.suggestion(id)? else {
                return respond_component(ctx, component, "Sugestão não encontrada.").await;
            };
            if !component_record_matches(
                component,
                &suggestion.guild_id,
                suggestion.message_id.as_deref(),
            ) {
                return respond_component(
                    ctx,
                    component,
                    "This suggestion does not belong to this panel.",
                )
                .await;
            }
            let vote = if kind == "up" { 1 } else { -1 };
            self.store
                .vote_suggestion(id, &component.user.id.to_string(), vote)?;
            let (up, down) = self.store.suggestion_votes(id)?;
            let author = suggestion_display::published_author(
                suggestion.id,
                &suggestion.author_id,
                &component.message,
            );
            let content = render_suggestion_message(
                suggestion.id,
                &author,
                &suggestion.content,
                &suggestion.status,
                up,
                down,
            );
            let user = if author != "Anonymous" {
                suggestion
                    .author_id
                    .parse::<u64>()
                    .ok()
                    .map(serenity::all::UserId::new)
            } else {
                None
            };
            let user = if let Some(user) = user {
                user.to_user(&ctx.http).await.ok()
            } else {
                None
            };
            let against = setting_string(
                &self.store,
                &guild_id.to_string(),
                "community.suggestions.vote_mode",
            )
            .as_deref()
                != Some("up_only");
            if !suggestion_message_fits(&content)
                || suggestion_display::publish(
                    ctx,
                    component.channel_id,
                    Some(component.message.id),
                    &suggestion_display::Content {
                        id: suggestion.id,
                        author: &author,
                        text: &suggestion.content,
                        status: &suggestion.status,
                        up,
                        down,
                    },
                    user.as_ref(),
                    against,
                )
                .await
                .is_err()
            {
                return respond_component(
                    ctx,
                    component,
                    "Vote saved, but the public panel could not be updated.",
                )
                .await;
            }
            return respond_component(ctx, component, "Voto registado.").await;
        }
        if let Some(raw_id) = component.data.custom_id.strip_prefix("giveaway:join:") {
            if !feature_enabled(
                &self.store,
                &guild_id.to_string(),
                "community.giveaways",
                None,
            ) {
                return respond_component(
                    ctx,
                    component,
                    "Os giveaways estão desativados neste servidor.",
                )
                .await;
            }
            let id = raw_id
                .parse::<i64>()
                .map_err(|_| anyhow::anyhow!("invalid giveaway button"))?;
            let Some(giveaway) = self.store.giveaway(id)? else {
                return respond_component(ctx, component, "Giveaway não encontrado.").await;
            };
            if !component_record_matches(
                component,
                &giveaway.guild_id,
                giveaway.message_id.as_deref(),
            ) || giveaway.channel_id != component.channel_id.to_string()
            {
                return respond_component(
                    ctx,
                    component,
                    "This giveaway does not belong to this panel.",
                )
                .await;
            }
            if giveaway.ended || giveaway.end_at <= Utc::now().timestamp_millis() {
                return respond_component(ctx, component, "Este giveaway já terminou.").await;
            }
            if let Some(role_id) = giveaway
                .required_role_id
                .as_deref()
                .and_then(|raw| raw.parse::<u64>().ok())
            {
                let member = guild_id.member(&ctx.http, component.user.id).await?;
                if !member.roles.iter().any(|role| role.get() == role_id) {
                    return respond_component(
                        ctx,
                        component,
                        "Não tens o cargo necessário para participar.",
                    )
                    .await;
                }
            }
            let update = giveaway_display::update_entry(
                &ctx.http,
                &self.store,
                id,
                &component.user.id.to_string(),
            )
            .await?;
            let response = match update.joined {
                Some(true) => "Entrada registada. Boa sorte!",
                Some(false) => "Saíste do giveaway.",
                None => "Este giveaway já terminou.",
            };
            if !update.panel_updated {
                return respond_component(
                    ctx,
                    component,
                    &format!(
                        "{} The participant total could not be updated on the public panel.",
                        english_bot_text(response)
                    ),
                )
                .await;
            }
            return respond_component(ctx, component, response).await;
        }
        if let Some(raw) = component.data.custom_id.strip_prefix("poll:") {
            if !feature_enabled(&self.store, &guild_id.to_string(), "management.polls", None) {
                return respond_component(
                    ctx,
                    component,
                    "As enquetes estão desativadas neste servidor.",
                )
                .await;
            }
            let mut parts = raw.split(':');
            let id = parts
                .next()
                .and_then(|value| value.parse::<i64>().ok())
                .ok_or_else(|| anyhow::anyhow!("invalid poll button"))?;
            let choice = parts
                .next()
                .and_then(|value| value.parse::<usize>().ok())
                .ok_or_else(|| anyhow::anyhow!("invalid poll choice"))?;
            let Some(poll) = self.store.poll(id)? else {
                return respond_component(ctx, component, "Poll não encontrada.").await;
            };
            if !component_record_matches(component, &poll.guild_id, poll.message_id.as_deref())
                || poll.channel_id != component.channel_id.to_string()
            {
                return respond_component(
                    ctx,
                    component,
                    "This poll does not belong to this panel.",
                )
                .await;
            }
            if poll.closed
                || poll.end_at <= Utc::now().timestamp_millis()
                || choice >= poll.options.len()
            {
                return respond_component(
                    ctx,
                    component,
                    "Esta poll já terminou ou a opção é inválida.",
                )
                .await;
            }
            if !self
                .store
                .vote_poll(id, &component.user.id.to_string(), choice)?
            {
                return respond_component(
                    ctx,
                    component,
                    "Esta poll já terminou ou a opção é inválida.",
                )
                .await;
            }
            return respond_component(
                ctx,
                component,
                "Voto registado; podes votar novamente para alterar.",
            )
            .await;
        }
        if let Some(raw_role_id) = component.data.custom_id.strip_prefix("role:toggle:") {
            if !feature_enabled(
                &self.store,
                &guild_id.to_string(),
                "community.role_panels",
                None,
            ) {
                return respond_component(
                    ctx,
                    component,
                    "Role panels are disabled in this server.",
                )
                .await;
            }
            let role_id = raw_role_id
                .parse::<u64>()
                .ok()
                .map(RoleId::new)
                .ok_or_else(|| anyhow::anyhow!("invalid role button"))?;
            let panel_key = format!("community.role_panel.{}", component.message.id);
            let panel = self
                .store
                .get_setting(&guild_id.to_string(), &panel_key)?
                .and_then(|raw| serde_json::from_str::<serde_json::Value>(&raw).ok());
            let panel_roles = panel
                .as_ref()
                .and_then(|value| value.get("role_ids"))
                .and_then(serde_json::Value::as_array)
                .map(|roles| {
                    roles
                        .iter()
                        .filter_map(serde_json::Value::as_u64)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            if !panel_roles.contains(&role_id.get()) {
                return respond_component(ctx, component, "This role panel is no longer valid.")
                    .await;
            }
            let selection_mode = panel
                .as_ref()
                .and_then(|value| value.get("selection_mode"))
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
                .or_else(|| {
                    setting_string(
                        &self.store,
                        &guild_id.to_string(),
                        "community.role_panels.selection_mode",
                    )
                })
                .unwrap_or_else(|| "multiple".to_string());
            let remove_on_unselect = panel
                .as_ref()
                .and_then(|value| value.get("remove_on_unselect"))
                .and_then(serde_json::Value::as_bool)
                .unwrap_or_else(|| {
                    setting_bool(
                        &self.store,
                        &guild_id.to_string(),
                        "community.role_panels.remove_on_unselect",
                        true,
                    )
                });
            let roles = guild_id.roles(&ctx.http).await?;
            let Some(role) = roles.get(&role_id) else {
                return respond_component(ctx, component, "That role no longer exists.").await;
            };
            if role.managed {
                return respond_component(
                    ctx,
                    component,
                    "Managed Discord roles cannot be assigned.",
                )
                .await;
            }
            let bot_user = ctx.http.get_current_user().await?;
            let bot_member = guild_id.member(&ctx.http, bot_user.id).await?;
            let bot_top_position = bot_member
                .roles
                .iter()
                .filter_map(|id| roles.get(id).map(|item| item.position))
                .max()
                .unwrap_or(0);
            if role.position >= bot_top_position {
                return respond_component(
                    ctx,
                    component,
                    "That role is above the Helper's highest role.",
                )
                .await;
            }
            let member = guild_id.member(&ctx.http, component.user.id).await?;
            let decision = evaluate_role_panel(&RolePanelObservation {
                panel_role_ids: panel_roles.clone(),
                selected_role_ids: member.roles.iter().map(|value| value.get()).collect(),
                clicked_role_id: role_id.get(),
                selection_mode: selection_mode.clone(),
                remove_on_unselect,
            });
            if !decision.allowed {
                return respond_component(ctx, component, "This role panel is no longer valid.")
                    .await;
            }
            if !decision.assign_clicked {
                for remove_id in decision.remove_role_ids {
                    member
                        .remove_role(&ctx.http, RoleId::new(remove_id))
                        .await?;
                }
                if decision.reason_code == "role_kept" {
                    return respond_component(
                        ctx,
                        component,
                        "This panel keeps selected roles assigned.",
                    )
                    .await;
                }
                return respond_component(ctx, component, "Role removed.").await;
            }
            if member.roles.contains(&role_id) {
                if !remove_on_unselect {
                    return respond_component(
                        ctx,
                        component,
                        "This panel keeps selected roles assigned.",
                    )
                    .await;
                }
                member.remove_role(&ctx.http, role_id).await?;
                return respond_component(ctx, component, "Cargo removido.").await;
            }
            for other_id in decision.remove_role_ids {
                member.remove_role(&ctx.http, RoleId::new(other_id)).await?;
            }
            member.add_role(&ctx.http, role_id).await?;
            return respond_component(ctx, component, "Cargo atribuído.").await;
        }
        if let Some(raw) = component.data.custom_id.strip_prefix("verify:") {
            if !feature_enabled(
                &self.store,
                &guild_id.to_string(),
                "protection.join_gate",
                Some("security.join_gate.enabled"),
            ) {
                return respond_component(
                    ctx,
                    component,
                    "The join gate is disabled in this server.",
                )
                .await;
            }
            let mut parts = raw.split(':');
            let expected_guild = parts.next().unwrap_or_default();
            if expected_guild != guild_id.to_string() {
                return respond_component(ctx, component, "Este painel pertence a outro servidor.")
                    .await;
            }
            let Some(verified_role_id) = setting_u64_optional(
                &self.store,
                &guild_id.to_string(),
                "security.join_gate.auto_role_id",
            ) else {
                return respond_component(
                    ctx,
                    component,
                    "This verification panel needs a configured verified-member role.",
                )
                .await;
            };
            let member = guild_id.member(&ctx.http, component.user.id).await?;
            let decision = evaluate_join_gate_verification(
                &member.roles,
                setting_u64_optional(
                    &self.store,
                    &guild_id.to_string(),
                    "security.join_gate.role_id",
                )
                .map(RoleId::new),
                RoleId::new(verified_role_id),
            );
            if decision.remove_quarantine_role
                && let Some(quarantine_role_id) = setting_u64_optional(
                    &self.store,
                    &guild_id.to_string(),
                    "security.join_gate.role_id",
                )
            {
                member
                    .remove_role(&ctx.http, RoleId::new(quarantine_role_id))
                    .await?;
            }
            if decision.assign_verified_role {
                member
                    .add_role(&ctx.http, RoleId::new(verified_role_id))
                    .await?;
            }
            if decision.already_verified {
                return respond_component(ctx, component, "You are already verified.").await;
            }
            return respond_component(ctx, component, "Verification complete; role assigned.")
                .await;
        }
        if let Some(raw) = component.data.custom_id.strip_prefix("welcome:step:") {
            let mut parts = raw.splitn(2, ':');
            let expected_guild = parts.next().unwrap_or_default();
            let step = parts.next().unwrap_or_default();
            if expected_guild != guild_id.to_string()
                || !matches!(step, "rules" | "introductions" | "channels" | "help")
            {
                return respond_component(ctx, component, "This welcome guide is no longer valid.")
                    .await;
            }
            let (enabled, welcome) = self
                .store
                .welcome_configuration(&guild_id.to_string())
                .unwrap_or((false, serde_json::json!({})));
            if !enabled || welcome["guideEnabled"].as_bool() != Some(true) {
                return respond_component(
                    ctx,
                    component,
                    "The guided welcome channel is disabled.",
                )
                .await;
            }
            let setting = match step {
                "rules" => "rulesChannel",
                "introductions" => "introductionsChannel",
                "channels" => "channelsChannel",
                "help" => "",
                _ => unreachable!(),
            };
            let destination = welcome[setting]
                .as_str()
                .and_then(|value| value.parse::<u64>().ok())
                .map(|id| format!(" <#{}>", id))
                .unwrap_or_default();
            let response = match step {
                "rules" => format!("Please read the server rules{}.", destination),
                "introductions" => format!("Introduce yourself to the community{}.", destination),
                "channels" => format!("Explore the channels and pick the ones you need{}.", destination),
                "help" => "Use /help to see the Helper commands, or open a ticket if you need staff support.".to_string(),
                _ => "Welcome to the server.".to_string(),
            };
            return respond_component(ctx, component, &response).await;
        }
        // Existing tickets can still be closed while disabled, but stale panels
        // must not create or reopen tickets, or claim work for a disabled module.
        if matches!(
            component.data.custom_id.as_str(),
            "ticket:claim" | "ticket:reopen"
        ) && !feature_enabled(&self.store, &guild_id.to_string(), "support.tickets", None)
        {
            return respond_component(ctx, component, "Tickets are disabled in this server.").await;
        }
        match component.data.custom_id.as_str() {
            "ticket:open" => {
                if !feature_enabled(
                    &self.store,
                    &guild_id.to_string(),
                    "support.tickets",
                    Some("feature.support.tickets"),
                ) {
                    return respond_component(
                        ctx,
                        component,
                        "Os tickets estão desativados neste servidor.",
                    )
                    .await;
                }
                let max_open = setting_u64(
                    &self.store,
                    &guild_id.to_string(),
                    "support.ticket.max_open",
                    1,
                )
                .clamp(1, 10);
                let open_count = self.store.active_ticket_count_for_user(
                    &guild_id.to_string(),
                    &component.user.id.to_string(),
                )?;
                let ticket_decision =
                    evaluate_tickets(&serde_json::json!({"maxOpen": max_open}), open_count);
                if !ticket_decision.allowed {
                    return respond_component(ctx, component, &ticket_decision.explanation).await;
                }
                let bot_id = ctx.http.get_current_user().await?.id;
                let visible = Permissions::VIEW_CHANNEL
                    | Permissions::SEND_MESSAGES
                    | Permissions::READ_MESSAGE_HISTORY;
                let staff_role_id = setting_u64_optional(
                    &self.store,
                    &guild_id.to_string(),
                    "support.ticket.staff_role_id",
                )
                .map(RoleId::new);
                if staff_role_id == Some(RoleId::new(guild_id.get())) {
                    return respond_component(
                        ctx,
                        component,
                        "Configure a support role other than @everyone.",
                    )
                    .await;
                }
                let mut overwrites = vec![
                    PermissionOverwrite {
                        allow: Permissions::empty(),
                        deny: Permissions::VIEW_CHANNEL,
                        kind: PermissionOverwriteType::Role(serenity::all::RoleId::new(
                            guild_id.get(),
                        )),
                    },
                    PermissionOverwrite {
                        allow: visible,
                        deny: Permissions::empty(),
                        kind: PermissionOverwriteType::Member(component.user.id),
                    },
                    PermissionOverwrite {
                        // Do not try to grant MENTION_EVERYONE to ourselves:
                        // Discord rejects permissions the bot does not possess.
                        allow: visible | Permissions::MANAGE_CHANNELS,
                        deny: Permissions::empty(),
                        kind: PermissionOverwriteType::Member(bot_id),
                    },
                ];
                if let Some(role_id) = staff_role_id {
                    overwrites.push(PermissionOverwrite {
                        allow: visible,
                        deny: Permissions::empty(),
                        kind: PermissionOverwriteType::Role(role_id),
                    });
                }
                let category_id = self
                    .store
                    .get_setting(&guild_id.to_string(), "support.ticket.category_id")?
                    .and_then(|value| value.parse::<u64>().ok())
                    .map(ChannelId::new);
                let mut create = CreateChannel::new(format!("ticket-{}", component.user.name))
                    .permissions(overwrites);
                if let Some(category_id) = category_id {
                    create = create.category(category_id);
                }
                let channel = guild_id.create_channel(&ctx.http, create).await?;
                if !self.store.try_open_ticket(
                    &guild_id.to_string(),
                    &component.user.id.to_string(),
                    &channel.id.to_string(),
                    max_open as u32,
                )? {
                    let _ = channel.id.delete(&ctx.http).await;
                    return respond_component(
                        ctx,
                        component,
                        &format!("You already have the maximum of {max_open} open ticket(s)."),
                    )
                    .await;
                }
                let sla_ms = self
                    .store
                    .get_setting(&guild_id.to_string(), "support.ticket.sla_ms")?
                    .and_then(|value| value.parse::<i64>().ok())
                    .unwrap_or(3_600_000);
                self.store.schedule_typed(
                    &guild_id.to_string(),
                    "ticket_sla",
                    &component.user.id.to_string(),
                    chrono::Utc::now().timestamp_millis() + sla_ms,
                    &serde_json::json!({"channel_id": channel.id.to_string()}).to_string(),
                )?;
                let content = ticket_opening_message(component.user.id, staff_role_id);
                let allowed_mentions = ticket_opening_mentions(component.user.id, staff_role_id);
                channel
                    .id
                    .send_message(
                        &ctx.http,
                        serenity::all::CreateMessage::new()
                            .content(content)
                            .allowed_mentions(allowed_mentions)
                            .components(vec![CreateActionRow::Buttons(vec![
                                CreateButton::new("ticket:claim")
                                    .label("Claim")
                                    .style(ButtonStyle::Secondary),
                                CreateButton::new("ticket:close")
                                    .label("Close")
                                    .style(ButtonStyle::Danger),
                            ])]),
                    )
                    .await?;
                respond_component(
                    ctx,
                    component,
                    &format!("Ticket created: <#{}>.", channel.id),
                )
                .await
            }
            "ticket:claim" => {
                let is_staff = ticket_actor_is_staff(
                    ctx,
                    guild_id,
                    component.channel_id,
                    component.user.id,
                    component.member.as_ref(),
                    setting_u64_optional(
                        &self.store,
                        &guild_id.to_string(),
                        "support.ticket.staff_role_id",
                    )
                    .map(RoleId::new),
                )
                .await;
                if !is_staff {
                    return respond_component(
                        ctx,
                        component,
                        "Only the support team can claim tickets. Ask an administrator to configure the staff role.",
                    )
                    .await;
                }
                let Some(ticket) = self
                    .store
                    .ticket_by_channel(&component.channel_id.to_string())?
                else {
                    return respond_component(ctx, component, "Ticket not found.").await;
                };
                if ticket.guild_id != guild_id.to_string() || ticket.status != "open" {
                    return respond_component(
                        ctx,
                        component,
                        "This ticket is not open in this server.",
                    )
                    .await;
                }
                if ticket.claimed_by.is_some() {
                    return respond_component(
                        ctx,
                        component,
                        "This ticket has already been claimed.",
                    )
                    .await;
                }
                if self.store.claim_ticket(
                    &component.channel_id.to_string(),
                    &component.user.id.to_string(),
                )? {
                    component
                        .channel_id
                        .say(
                            &ctx.http,
                            format!("Ticket claimed by <@{}>.", component.user.id),
                        )
                        .await?;
                    respond_component(ctx, component, "Ticket claimed.").await
                } else {
                    respond_component(
                        ctx,
                        component,
                        "This ticket is closed or has already been claimed.",
                    )
                    .await
                }
            }
            "ticket:reopen" => {
                let Some(ticket) = self
                    .store
                    .ticket_by_channel(&component.channel_id.to_string())?
                else {
                    return respond_component(ctx, component, "Ticket not found.").await;
                };
                let is_opener = ticket.user_id == component.user.id.to_string();
                let is_staff = ticket_actor_is_staff(
                    ctx,
                    guild_id,
                    component.channel_id,
                    component.user.id,
                    component.member.as_ref(),
                    setting_u64_optional(
                        &self.store,
                        &guild_id.to_string(),
                        "support.ticket.staff_role_id",
                    )
                    .map(RoleId::new),
                )
                .await;
                if ticket.guild_id != guild_id.to_string() || (!is_opener && !is_staff) {
                    return respond_component(
                        ctx,
                        component,
                        "Only the ticket author or support team can reopen this ticket.",
                    )
                    .await;
                }
                let max_open = setting_u64(
                    &self.store,
                    &guild_id.to_string(),
                    "support.ticket.max_open",
                    1,
                )
                .clamp(1, 10);
                if self
                    .store
                    .active_ticket_count_for_user(&ticket.guild_id, &ticket.user_id)?
                    >= max_open as u32
                {
                    return respond_component(
                        ctx,
                        component,
                        "The ticket author already has the maximum number of open tickets.",
                    )
                    .await;
                }
                if !self
                    .store
                    .reopen_ticket(&component.channel_id.to_string())?
                {
                    return respond_component(
                        ctx,
                        component,
                        "Este ticket já está aberto ou não existe.",
                    )
                    .await;
                }
                component
                    .channel_id
                    .edit(
                        &ctx.http,
                        EditChannel::new().name(format!("ticket-{}", ticket.user_id)),
                    )
                    .await?;
                component
                    .channel_id
                    .send_message(
                        &ctx.http,
                        serenity::all::CreateMessage::new()
                            .content("Ticket reopened. The team can continue responding.")
                            .components(vec![CreateActionRow::Buttons(vec![
                                CreateButton::new("ticket:claim")
                                    .label("Claim")
                                    .style(ButtonStyle::Secondary),
                                CreateButton::new("ticket:close")
                                    .label("Close")
                                    .style(ButtonStyle::Danger),
                            ])]),
                    )
                    .await?;
                respond_component(ctx, component, "Ticket reopened.").await
            }
            "ticket:close" => {
                let ticket = self
                    .store
                    .ticket_by_channel(&component.channel_id.to_string())?;
                let Some(ticket_for_auth) = ticket.as_ref() else {
                    return respond_component(ctx, component, "Ticket not found.").await;
                };
                let is_opener = ticket_for_auth.user_id == component.user.id.to_string();
                let is_staff = ticket_actor_is_staff(
                    ctx,
                    guild_id,
                    component.channel_id,
                    component.user.id,
                    component.member.as_ref(),
                    setting_u64_optional(
                        &self.store,
                        &guild_id.to_string(),
                        "support.ticket.staff_role_id",
                    )
                    .map(RoleId::new),
                )
                .await;
                if ticket_for_auth.guild_id != guild_id.to_string() || (!is_opener && !is_staff) {
                    return respond_component(
                        ctx,
                        component,
                        "Only the ticket author or support team can close this ticket.",
                    )
                    .await;
                }
                if self.store.close_ticket(&component.channel_id.to_string())? {
                    if let Some(raw_channel) = self.store.get_setting(
                        &guild_id.to_string(),
                        "support.ticket.transcript_channel_id",
                    )? && let Ok(transcript_channel) = raw_channel.parse::<u64>()
                    {
                        let messages = component
                            .channel_id
                            .messages(&ctx.http, serenity::all::GetMessages::new().limit(100))
                            .await
                            .unwrap_or_default();
                        let opener = ticket
                            .as_ref()
                            .map(|ticket| format!("<@{}>", ticket.user_id))
                            .unwrap_or_else(|| "unknown".to_string());
                        let mut transcript = format!("Ticket transcript for {opener}\n");
                        for message in messages.iter().rev() {
                            transcript.push_str(&format!(
                                "{}: {}\n",
                                message.author.name, message.content
                            ));
                        }
                        for chunk in transcript.as_bytes().chunks(1_800) {
                            let text = String::from_utf8_lossy(chunk);
                            let _ = ChannelId::new(transcript_channel)
                                .say(&ctx.http, text)
                                .await;
                        }
                    }
                    component
                        .channel_id
                        .edit(
                            &ctx.http,
                            EditChannel::new()
                                .name(format!("closed-ticket-{}", ticket_for_auth.user_id)),
                        )
                        .await?;
                    component
                        .channel_id
                        .send_message(
                            &ctx.http,
                            serenity::all::CreateMessage::new()
                                .content("Ticket closed. The history was preserved; the author or team can reopen it.")
                                .components(vec![CreateActionRow::Buttons(vec![
                                    CreateButton::new("ticket:reopen")
                                        .label("Reopen")
                                        .style(ButtonStyle::Success),
                                ])]),
                        )
                        .await?;
                    respond_component(
                        ctx,
                        component,
                        "Ticket closed. The channel and its history were preserved.",
                    )
                    .await?;
                } else {
                    respond_component(ctx, component, "This ticket is already closed.").await?;
                }
                Ok(())
            }
            _ => respond_component(ctx, component, "Botão desconhecido.").await,
        }
    }
}

fn edit_member_roles<'a>(
    event: &'a MessageUpdateEvent,
    message: Option<&'a serenity::all::Message>,
) -> Option<&'a [RoleId]> {
    event
        .member
        .as_ref()
        .and_then(|member| member.as_deref())
        .or_else(|| message.and_then(|message| message.member.as_deref()))
        .map(|member| member.roles.as_slice())
}

fn discord_error_code(error: &serenity::Error, code: isize) -> bool {
    matches!(error, serenity::Error::Http(serenity::http::HttpError::UnsuccessfulRequest(response)) if response.error.code == code)
}

fn component_record_matches(
    component: &serenity::all::ComponentInteraction,
    guild_id: &str,
    message_id: Option<&str>,
) -> bool {
    component
        .guild_id
        .is_some_and(|guild| guild.to_string() == guild_id)
        && message_id.is_some_and(|message| message == component.message.id.to_string())
}

fn command_response_ephemeral(store: &Store, command: &CommandInteraction) -> bool {
    match command.data.name.as_str() {
        "ping" | "rank" => false,
        "leaderboard" => !command.guild_id.is_some_and(|guild| {
            setting_bool(
                store,
                &guild.to_string(),
                "community.leaderboard.public",
                true,
            )
        }),
        "serverstats" => !command.guild_id.is_some_and(|guild| {
            setting_bool(store, &guild.to_string(), "insights.stats.public", false)
        }),
        _ => true,
    }
}

async fn respond(ctx: &Context, command: &CommandInteraction, content: &str) -> Result<()> {
    command
        .edit_response(
            ctx,
            EditInteractionResponse::new()
                .content(english_bot_text(content))
                .allowed_mentions(CreateAllowedMentions::new()),
        )
        .await?;
    Ok(())
}

async fn respond_component(
    ctx: &Context,
    component: &serenity::all::ComponentInteraction,
    content: &str,
) -> Result<()> {
    component
        .edit_response(
            ctx,
            EditInteractionResponse::new()
                .content(english_bot_text(content))
                .allowed_mentions(CreateAllowedMentions::new()),
        )
        .await?;
    Ok(())
}

/// Translate legacy Portuguese system text at the Discord boundary.
///
/// Configuration values, tag bodies and user supplied content remain untouched;
/// only known Helper-owned phrases are translated. This keeps existing guild
/// settings compatible while ensuring command/component feedback is English.
fn english_bot_text(input: &str) -> String {
    const REPLACEMENTS: &[(&str, &str)] = &[
        // Keep all Helper-owned command and component feedback in English.
        // These entries intentionally cover the correctly encoded strings
        // still present in older handlers; the mojibake variants below keep
        // responses from legacy persisted/configured paths readable too.
        (
            "Este comando só pode ser usado num servidor.",
            "This command can only be used in a server.",
        ),
        ("Indica um membro.", "Specify a member."),
        ("Indica um utilizador.", "Specify a user."),
        ("Indica um ID de utilizador.", "Specify a user ID."),
        ("ID de utilizador inválido.", "Invalid user ID."),
        ("Indica um canal válido.", "Specify a valid channel."),
        (
            "Indica pelo menos um cargo válido.",
            "Specify at least one valid role.",
        ),
        (
            "Indica uma pergunta e pelo menos duas opções.",
            "Specify a question and at least two options.",
        ),
        (
            "O conteúdo não pode exceder 500 caracteres.",
            "Content cannot exceed 500 characters.",
        ),
        (
            "Duração inválida. Usa 10m, 2h ou 1d.",
            "Invalid duration. Use 10m, 2h or 1d.",
        ),
        ("Nome ou conteúdo inválido.", "Invalid name or content."),
        (
            "Nome, condição ou resposta inválidos.",
            "Invalid name, condition or response.",
        ),
        (
            "Nome, local ou descrição inválidos.",
            "Invalid name, location or description.",
        ),
        (
            "Indica prioridade, categoria ou nota.",
            "Specify a priority, category or note.",
        ),
        ("Prioridade inválida.", "Invalid priority."),
        (
            "As sugestões estão desativadas neste servidor. Ativa-as no painel.",
            "Suggestions are disabled in this server. Enable them in the dashboard.",
        ),
        (
            "A sugestão deve ter entre 3 e 1000 caracteres.",
            "The suggestion must be between 3 and 1,000 characters.",
        ),
        (
            "Os giveaways estão desativados neste servidor. Ativa-os no painel.",
            "Giveaways are disabled in this server. Enable them in the dashboard.",
        ),
        (
            "O prémio deve ter entre 1 e 200 caracteres.",
            "The prize must be between 1 and 200 characters.",
        ),
        (
            "As enquetes estão desativadas neste servidor. Ativa-as no painel.",
            "Polls are disabled in this server. Enable them in the dashboard.",
        ),
        (
            "Indica uma pergunta e pelo menos duas opções.",
            "Specify a question and at least two options.",
        ),
        (
            "Esse membro não está em quarantine.",
            "That member is not quarantined.",
        ),
        (
            "Configura primeiro `/join-gate` com um cargo de verificação.",
            "Configure `/join-gate` first with a verification role.",
        ),
        (
            "Ativa primeiro o `/join-gate`; o painel não deve ficar exposto enquanto o gate está desligado.",
            "Enable `/join-gate` first; do not expose the panel while the gate is disabled.",
        ),
        (
            "Os eventos estão desativados neste servidor. Ativa-os no painel.",
            "Events are disabled in this server. Enable them in the dashboard.",
        ),
        (
            "A lotação deve estar entre 1 e 100000.",
            "Capacity must be between 1 and 100,000.",
        ),
        (
            "Nome, local ou descrição inválidos.",
            "Invalid name, location or description.",
        ),
        (
            "Indica um ID de evento válido.",
            "Specify a valid event ID.",
        ),
        (
            "Não encontrei esse evento neste servidor.",
            "That event was not found in this server.",
        ),
        (
            "Este evento já terminou ou foi cancelado.",
            "This event has already ended or was cancelled.",
        ),
        (
            "Não tens uma inscrição neste evento.",
            "You are not registered for this event.",
        ),
        (
            "O teu check-in já está registado.",
            "Your check-in is already recorded.",
        ),
        (
            "Workflow não encontrado neste servidor.",
            "Workflow not found in this server.",
        ),
        (
            "Este canal não é um ticket do Helper.",
            "This channel is not a Helper ticket.",
        ),
        (
            "Só o autor do ticket pode avaliá-lo.",
            "Only the ticket author can rate it.",
        ),
        (
            "A avaliação tem de ser entre 1 e 5.",
            "The rating must be between 1 and 5.",
        ),
        (
            "Só podes avaliar um ticket fechado.",
            "You can only rate a closed ticket.",
        ),
        (
            "Não foi possível guardar a avaliação.",
            "Unable to save the rating.",
        ),
        (
            "Os painéis de cargos estão desativados neste servidor. Ativa-os no painel.",
            "Role panels are disabled in this server. Enable them in the dashboard.",
        ),
        (
            "Indica pelo menos um cargo válido.",
            "Specify at least one valid role.",
        ),
        ("Sugestão não encontrada.", "Suggestion not found."),
        ("Voto registado.", "Vote recorded."),
        ("Giveaway não encontrado.", "Giveaway not found."),
        (
            "Este giveaway já terminou.",
            "This giveaway has already ended.",
        ),
        ("Saíste do giveaway.", "You left the giveaway."),
        ("Poll não encontrada.", "Poll not found."),
        ("Cargo atribuído.", "Role assigned."),
        ("Cargo removido.", "Role removed."),
        (
            "Painel de verificação inválido.",
            "Invalid verification panel.",
        ),
        ("Já estás verificado.", "You are already verified."),
        ("Botão desconhecido.", "Unknown button."),
        (
            "Setup guiado: escolhe pelo menos um m\u{00f3}dulo (Security, Support, Events, Community, Automate ou Insights) e executa novamente. Depois confirma as permiss\u{00f5}es com `/permissions`.",
            "Guided setup: choose at least one module (Security, Support, Events, Community, Automate or Insights), then run it again. Confirm permissions with `/permissions`.",
        ),
        (
            "e depois configura cada m\u{00f3}dulo.",
            "and then configure each module.",
        ),
        ("Isolamento por guild ativo", "Guild isolation enabled"),
        (
            "Privacy export/delete dispon\u{00ed}vel",
            "Privacy export/delete available",
        ),
        (
            "(o endpoint permanece desligado at\u{00e9} ao rollout aprovado).",
            "(the endpoint remains disabled until the approved rollout).",
        ),
        (
            "Este comando só pode ser usado num servidor.",
            "This command can only be used in a server.",
        ),
        ("Indica um membro.", "Specify a member."),
        ("Indica um utilizador.", "Specify a user."),
        ("Indica um ID de utilizador.", "Specify a user ID."),
        ("ID de utilizador inválido.", "Invalid user ID."),
        ("Indica um canal válido.", "Specify a valid channel."),
        (
            "Indica pelo menos um cargo válido.",
            "Specify at least one valid role.",
        ),
        (
            "Indica uma pergunta e pelo menos duas opções.",
            "Specify a question and at least two options.",
        ),
        (
            "Indica prioridade, categoria ou nota.",
            "Specify a priority, category or note.",
        ),
        (
            "Indica pelo menos um campo para alterar.",
            "Specify at least one field to change.",
        ),
        (
            "A lotação deve estar entre 1 e 100000.",
            "Capacity must be between 1 and 100,000.",
        ),
        (
            "A avaliação tem de ser entre 1 e 5.",
            "The rating must be between 1 and 5.",
        ),
        (
            "Não foi possível registar o check-in.",
            "Unable to record the check-in.",
        ),
        (
            "Não tens o cargo necessário para participar.",
            "You do not have the required role to participate.",
        ),
        (
            "Esta poll já terminou ou a opção é inválida.",
            "This poll has ended or the option is invalid.",
        ),
        (
            "Os tickets estão desativados neste servidor.",
            "Tickets are disabled in this server.",
        ),
        (
            "Este ticket já está aberto ou não existe.",
            "This ticket is already open or does not exist.",
        ),
        ("Ticket atualizado: categoria ", "Ticket updated: category "),
        (
            "Ticket atualizado: prioridade ",
            "Ticket updated: priority ",
        ),
        ("Ticket updated: categoria ", "Ticket updated: category "),
        ("Ticket updated: prioridade ", "Ticket updated: priority "),
        (
            "O conteúdo não pode exceder 500 caracteres.",
            "Content cannot exceed 500 characters.",
        ),
        (
            "Duração inválida. Usa 10m, 2h ou 1d.",
            "Invalid duration. Use 10m, 2h or 1d.",
        ),
        (
            "Duração inválida. Usa formatos como 10m, 2h ou 1d.",
            "Invalid duration. Use formats such as 10m, 2h or 1d.",
        ),
        ("Nome ou conteúdo inválido.", "Invalid name or content."),
        (
            "Nome, condição ou resposta inválidos.",
            "Invalid name, condition or response.",
        ),
        (
            "Nome, local ou descrição inválidos.",
            "Invalid name, location or description.",
        ),
        (
            "A mensagem de teste não pode exceder 2000 caracteres.",
            "The test message cannot exceed 2,000 characters.",
        ),
        (
            "As sugestões estão desativadas neste servidor. Ativa-as no painel.",
            "Suggestions are disabled in this server. Enable them in the dashboard.",
        ),
        (
            "A sugestão deve ter entre 3 e 1000 caracteres.",
            "The suggestion must be between 3 and 1,000 characters.",
        ),
        (
            "Estado inválido: pending, approved, denied ou considered.",
            "Invalid status: pending, approved, denied or considered.",
        ),
        (
            "Os giveaways estão desativados neste servidor. Ativa-os no painel.",
            "Giveaways are disabled in this server. Enable them in the dashboard.",
        ),
        (
            "Giveaway não encontrado ou já terminado.",
            "Giveaway not found or already ended.",
        ),
        (
            "Giveaway não encontrado, ainda ativo ou sem participantes.",
            "Giveaway not found, still active or without participants.",
        ),
        (
            "O prémio deve ter entre 1 e 200 caracteres.",
            "The prize must be between 1 and 200 characters.",
        ),
        (
            "As enquetes estão desativadas neste servidor. Ativa-as no painel.",
            "Polls are disabled in this server. Enable them in the dashboard.",
        ),
        (
            "Esse membro não está em quarantine.",
            "That member is not quarantined.",
        ),
        (
            "Configura primeiro `/join-gate` com um cargo de verificação.",
            "Configure `/join-gate` first with a verification role.",
        ),
        (
            "Ativa primeiro o `/join-gate`; o painel não deve ficar exposto enquanto o gate está desligado.",
            "Enable `/join-gate` first; do not expose the panel while the gate is disabled.",
        ),
        (
            "Os eventos estão desativados neste servidor. Ativa-os no painel.",
            "Events are disabled in this server. Enable them in the dashboard.",
        ),
        (
            "A lotação deve estar entre 1 e 100000.",
            "Capacity must be between 1 and 100,000.",
        ),
        (
            "Não existem eventos agendados neste servidor.",
            "There are no scheduled events in this server.",
        ),
        (
            "Não encontrei esse evento neste servidor.",
            "That event was not found in this server.",
        ),
        (
            "Eventos concluídos ou cancelados não podem ser editados.",
            "Completed or cancelled events cannot be edited.",
        ),
        (
            "Indica um ID de evento válido.",
            "Specify a valid event ID.",
        ),
        (
            "O nome tem de ter entre 1 e 100 caracteres.",
            "The name must be between 1 and 100 characters.",
        ),
        (
            "A localização só pode ser alterada em eventos externos e deve ter 1–100 caracteres.",
            "Location can only be changed for external events and must be 1–100 characters.",
        ),
        (
            "A descrição não pode exceder 1000 caracteres.",
            "The description cannot exceed 1,000 characters.",
        ),
        (
            "A nova data de início tem de estar no futuro.",
            "The new start date must be in the future.",
        ),
        (
            "O fim tem de ser depois do início.",
            "The end must be after the start.",
        ),
        (
            "O evento não pode durar mais de 365 dias.",
            "The event cannot last longer than 365 days.",
        ),
        (
            "Este evento já terminou ou foi cancelado.",
            "This event has already ended or was cancelled.",
        ),
        (
            "Não tens uma inscrição neste evento.",
            "You are not registered for this event.",
        ),
        (
            "Inscreve-te primeiro com `/event-register`.",
            "Register first with `/event-register`.",
        ),
        (
            "O teu check-in já está registado.",
            "Your check-in is already recorded.",
        ),
        (
            "Nome, condição ou resposta inválidos.",
            "Invalid name, condition or response.",
        ),
        (
            "Workflow não encontrado neste servidor.",
            "Workflow not found in this server.",
        ),
        (
            "A mensagem de teste não pode exceder 2000 caracteres.",
            "The test message cannot exceed 2,000 characters.",
        ),
        (
            "O SLA deve estar entre 5 e 1440 minutos.",
            "SLA must be between 5 and 1,440 minutes.",
        ),
        (
            "Este canal não é um ticket do Helper.",
            "This channel is not a Helper ticket.",
        ),
        (
            "Só o autor do ticket pode avaliá-lo.",
            "Only the ticket author can rate it.",
        ),
        (
            "A avaliação tem de ser entre 1 e 5.",
            "The rating must be between 1 and 5.",
        ),
        (
            "Só podes avaliar um ticket fechado.",
            "You can only rate a closed ticket.",
        ),
        (
            "Não foi possível guardar a avaliação.",
            "Unable to save the rating.",
        ),
        (
            "Os painéis de cargos estão desativados neste servidor. Ativa-os no painel.",
            "Role panels are disabled in this server. Enable them in the dashboard.",
        ),
        (
            "Este botão só funciona num servidor.",
            "This button can only be used in a server.",
        ),
        ("Sugestão não encontrada.", "Suggestion not found."),
        ("Voto registado.", "Vote recorded."),
        ("Giveaway não encontrado.", "Giveaway not found."),
        (
            "Este giveaway já terminou.",
            "This giveaway has already ended.",
        ),
        (
            "Entrada registada. Boa sorte!",
            "Entry recorded. Good luck!",
        ),
        ("Saíste do giveaway.", "You left the giveaway."),
        ("Poll não encontrada.", "Poll not found."),
        ("Cargo removido.", "Role removed."),
        ("Cargo atribuído.", "Role assigned."),
        (
            "Este painel pertence a outro servidor.",
            "This panel belongs to another server.",
        ),
        (
            "Painel de verificação inválido.",
            "Invalid verification panel.",
        ),
        ("Já estás verificado.", "You are already verified."),
        (
            "Verificacao concluida; cargo atribuido.",
            "Verification complete; role assigned.",
        ),
        ("Botão desconhecido.", "Unknown button."),
        ("Tag não encontrada.", "Tag not found."),
        ("Ainda não existem tags.", "There are no tags yet."),
        ("Ainda não existem dados de XP.", "There is no XP data yet."),
        ("Tag `", "Tag `"),
        ("` guardada.", "` saved."),
        ("` eliminada.", "` deleted."),
        (
            "Este comando só pode ser usado num servidor.",
            "This command can only be used in a server.",
        ),
        ("AFK definido:", "AFK status set:"),
        ("AFK removido.", "AFK status removed."),
        ("Evento nativo", "Native event"),
        ("conta criada em", "account created at"),
        ("Aviso criado como caso", "Warning created as case"),
        ("Registo #", "Record #"),
        (
            "Caso não encontrado neste servidor.",
            "Case not found in this server.",
        ),
        ("Não existem casos para", "There are no cases for"),
        ("Sugestão publicada.", "Suggestion published."),
        (
            "Sugestão não encontrada neste servidor.",
            "Suggestion not found in this server.",
        ),
        ("Giveaway criado.", "Giveaway created."),
        ("Giveaway terminado.", "Giveaway ended."),
        (
            "Não existem giveaways ativos.",
            "There are no active giveaways.",
        ),
        ("Poll #{} criada.", "Poll #{} created."),
        (
            "<@{}> colocado em quarantine como caso",
            "<@{}> quarantined as case",
        ),
        ("Quarantine removida de", "Quarantine removed from"),
        (
            "Painel de verificação publicado neste canal.",
            "Verification panel posted in this channel.",
        ),
        (
            "Join gate desativado; as definições guardadas podem ser reativadas.",
            "Join gate disabled; saved settings can be re-enabled.",
        ),
        ("Lockdown aplicado em", "Lockdown applied to"),
        ("Lockdown removido de", "Lockdown removed from"),
        ("Evento nativo #{} criado:", "Native event #{} created:"),
        (
            "Não existem workflows configurados.",
            "There are no workflows configured.",
        ),
        ("Workflow #{} criado.", "Workflow #{} created."),
        (
            "Configuração de tickets guardada.",
            "Ticket configuration saved.",
        ),
        ("Painel de tickets criado em", "Ticket panel created in"),
        ("Ticket atualizado:", "Ticket updated:"),
        ("Painel de cargos criado.", "Role panel created."),
        // Current Rust literals are UTF-8, while older releases persisted a
        // few mojibake variants. Keep both forms so Helper-owned responses
        // remain English after an upgrade; user content is not translated.
        ("Ol\u{00e1} ", "Hello "),
        (
            "Este comando s\u{00f3} pode ser usado num servidor.",
            "This command can only be used in a server.",
        ),
        (
            "O XP card est\u{00e1} desativado neste servidor. Ativa-o no painel primeiro.",
            "The XP card is disabled in this server. Enable it in the dashboard first.",
        ),
        (
            "N\u{00e3}o tens a permiss\u{00e3}o necess\u{00e1}ria para este comando.",
            "You do not have the required permission for this command.",
        ),
        (
            "N\u{00e3}o foi poss\u{00ed}vel consultar o plano agora; o Helper mant\u{00e9}m o \u{00fa}ltimo snapshot seguro.",
            "Unable to check the plan right now; Helper is keeping the last safe snapshot.",
        ),
        (
            "Enviei os teus dados por mensagem privada.",
            "I sent your data by direct message.",
        ),
        (
            "N\u{00e3}o consegui enviar mensagem privada. Ativa as DMs e tenta novamente.",
            "I could not send a direct message. Enable DMs and try again.",
        ),
        (
            "Ainda n\u{00e3}o existem casos neste servidor.",
            "There are no cases in this server yet.",
        ),
        ("Indica um membro.", "Specify a member."),
        (
            "O conte\u{00fa}do n\u{00e3}o pode exceder 500 caracteres.",
            "Content cannot exceed 500 characters.",
        ),
        (
            "N\u{00e3}o foi poss\u{00ed}vel remover o timeout; confirma as permiss\u{00f5}es.",
            "Unable to remove the timeout; check permissions.",
        ),
        (
            "N\u{00e3}o foi poss\u{00ed}vel remover o ban.",
            "Unable to remove the ban.",
        ),
        (
            "N\u{00e3}o encontrei mensagens para apagar.",
            "No messages found to delete.",
        ),
        (
            "N\u{00e3}o foi poss\u{00ed}vel executar a a\u{00e7}\u{00e3}o; confirma as permiss\u{00f5}es e a hierarquia de cargos.",
            "Unable to perform the action; check permissions and role hierarchy.",
        ),
        (
            "N\u{00e3}o tinhas AFK definido.",
            "You did not have an AFK status set.",
        ),
        ("Tag n\u{00e3}o encontrada.", "Tag not found."),
        ("Ainda n\u{00e3}o existem tags.", "There are no tags yet."),
        (
            "Ainda n\u{00e3}o existem dados de XP.",
            "There is no XP data yet.",
        ),
        (
            "As sugest\u{00f5}es est\u{00e3}o desativadas neste servidor. Ativa-as no painel.",
            "Suggestions are disabled in this server. Enable them in the dashboard.",
        ),
        (
            "Os giveaways est\u{00e3}o desativados neste servidor. Ativa-os no painel.",
            "Giveaways are disabled in this server. Enable them in the dashboard.",
        ),
        (
            "As enquetes est\u{00e3}o desativadas neste servidor. Ativa-as no painel.",
            "Polls are disabled in this server. Enable them in the dashboard.",
        ),
        (
            "Os eventos est\u{00e3}o desativados neste servidor. Ativa-os no painel.",
            "Events are disabled in this server. Enable them in the dashboard.",
        ),
        (
            "Workflow n\u{00e3}o encontrado neste servidor.",
            "Workflow not found in this server.",
        ),
        (
            "Giveaway n\u{00e3}o encontrado ou j\u{00e1} terminado.",
            "Giveaway not found or already ended.",
        ),
        (
            "N\u{00e3}o existem giveaways ativos.",
            "There are no active giveaways.",
        ),
        (
            "N\u{00e3}o encontrei esse evento neste servidor.",
            "That event was not found in this server.",
        ),
        (
            "N\u{00e3}o tens uma inscri\u{00e7}\u{00e3}o neste evento.",
            "You are not registered for this event.",
        ),
        (
            "N\u{00e3}o foi poss\u{00ed}vel registar o check-in.",
            "Unable to record the check-in.",
        ),
        (
            "N\u{00e3}o foi poss\u{00ed}vel guardar a avalia\u{00e7}\u{00e3}o.",
            "Unable to save the rating.",
        ),
        (
            "Os pain\u{00e9}is de cargos est\u{00e3}o desativados neste servidor. Ativa-os no painel.",
            "Role panels are disabled in this server. Enable them in the dashboard.",
        ),
        (
            "Os tickets est\u{00e3}o desativados neste servidor.",
            "Tickets are disabled in this server.",
        ),
        (
            "Este canal n\u{00e3}o \u{00e9} um ticket do Helper.",
            "This channel is not a Helper ticket.",
        ),
        ("Bot\u{00e3}o desconhecido.", "Unknown button."),
        ("Olá ", "Hello "),
        ("Explica aqui o que precisas.", "Tell us what you need."),
        (
            "Este comando só pode ser usado num servidor.",
            "This command can only be used in a server.",
        ),
        (
            "Este comando só pode ser usado num servidor.",
            "This command can only be used in a server.",
        ),
        ("Indica um membro.", "Specify a member."),
        ("Indica um utilizador.", "Specify a user."),
        ("Indica um ID de utilizador.", "Specify a user ID."),
        ("ID de utilizador inválido.", "Invalid user ID."),
        ("Indica um canal válido.", "Specify a valid channel."),
        (
            "Indica pelo menos um cargo válido.",
            "Specify at least one valid role.",
        ),
        (
            "Indica uma pergunta e pelo menos duas opções.",
            "Specify a question and at least two options.",
        ),
        (
            "Indica prioridade, categoria ou nota.",
            "Specify a priority, category or note.",
        ),
        (
            "Indica pelo menos um campo para alterar.",
            "Specify at least one field to change.",
        ),
        (
            "Não foi possível concluir esta ação.",
            "Unable to complete this action.",
        ),
        (
            "Nao foi possivel executar o ban; confirma as permissoes e a hierarquia.",
            "Unable to ban this member; check permissions and role hierarchy.",
        ),
        (
            "Não tens a permissão necessária para este comando.",
            "You do not have the required permission for this command.",
        ),
        (
            "O conteúdo não pode exceder 500 caracteres.",
            "Content cannot exceed 500 characters.",
        ),
        (
            "A mensagem de teste não pode exceder 2000 caracteres.",
            "The test message cannot exceed 2,000 characters.",
        ),
        (
            "O lembrete não pode exceder 500 caracteres.",
            "The reminder cannot exceed 500 characters.",
        ),
        ("Nome ou conteúdo inválido.", "Invalid name or content."),
        (
            "Nome, condição ou resposta inválidos.",
            "Invalid name, condition or response.",
        ),
        (
            "Nome, local ou descrição inválidos.",
            "Invalid name, location or description.",
        ),
        (
            "Duração inválida. Usa formatos como 10m, 2h ou 1d.",
            "Invalid duration. Use formats such as 10m, 2h or 1d.",
        ),
        (
            "Duração inválida. Usa 10m, 2h ou 1d.",
            "Invalid duration. Use 10m, 2h or 1d.",
        ),
        (
            "Duração inválida. Usa 10m, 2h ou 1d.",
            "Invalid duration. Use 10m, 2h or 1d.",
        ),
        (
            "O prémio deve ter entre 1 e 200 caracteres.",
            "The prize must be between 1 and 200 characters.",
        ),
        (
            "As sugestões estão desativadas neste servidor. Ativa-as no painel.",
            "Suggestions are disabled in this server. Enable them in the dashboard.",
        ),
        (
            "Os giveaways estão desativados neste servidor. Ativa-os no painel.",
            "Giveaways are disabled in this server. Enable them in the dashboard.",
        ),
        (
            "As enquetes estão desativadas neste servidor. Ativa-as no painel.",
            "Polls are disabled in this server. Enable them in the dashboard.",
        ),
        (
            "Os eventos estão desativados neste servidor. Ativa-os no painel.",
            "Events are disabled in this server. Enable them in the dashboard.",
        ),
        (
            "Workflow não encontrado neste servidor.",
            "Workflow not found in this server.",
        ),
        (
            "Não encontrei esse evento neste servidor.",
            "That event was not found in this server.",
        ),
        (
            "Não encontrei esse evento neste servidor.",
            "That event was not found in this server.",
        ),
        (
            "Giveaway não encontrado ou já terminado.",
            "Giveaway not found or already ended.",
        ),
        (
            "Esse membro não está em quarantine.",
            "That member is not quarantined.",
        ),
        (
            "Configura primeiro `/join-gate` com um cargo de verificação.",
            "Configure `/join-gate` first with a verification role.",
        ),
        (
            "Configura primeiro `/join-gate` com um cargo de verificação.",
            "Configure `/join-gate` first with a verification role.",
        ),
        (
            "Ativa primeiro o `/join-gate`; o painel não deve ficar exposto enquanto o gate está desligado.",
            "Enable `/join-gate` first; do not expose the panel while the gate is disabled.",
        ),
        (
            "Ativa primeiro o `/join-gate`; o painel não deve ficar exposto enquanto o gate está desligado.",
            "Enable `/join-gate` first; do not expose the panel while the gate is disabled.",
        ),
        (
            "Carrega no botão para receber o cargo de membro verificado.",
            "Click the button to receive the verified member role.",
        ),
        (
            "Carrega no botão para receber o cargo de membro verificado.",
            "Click the button to receive the verified member role.",
        ),
        (
            "Painel de verificação publicado neste canal.",
            "Verification panel posted in this channel.",
        ),
        (
            "Painel de verificação publicado neste canal.",
            "Verification panel posted in this channel.",
        ),
        ("Painel de cargos criado.", "Role panel created."),
        ("Painel criado.", "Panel created."),
        ("Comando desconhecido.", "Unknown command."),
        ("Dados voluntários apagados.", "Voluntary data deleted."),
        ("Dados voluntários apagados.", "Voluntary data deleted."),
        ("Ticket criado:", "Ticket created:"),
        ("Ticket reaberto.", "Ticket reopened."),
        (
            "Ticket fechado e arquivado. O canal não foi apagado.",
            "Ticket closed and archived. The channel was not deleted.",
        ),
        (
            "Ticket fechado e arquivado. O canal não foi apagado.",
            "Ticket closed and archived. The channel was not deleted.",
        ),
        (
            "Este ticket já está aberto ou não existe.",
            "This ticket is already open or does not exist.",
        ),
        (
            "Este ticket já está aberto ou não existe.",
            "This ticket is already open or does not exist.",
        ),
        (
            "Este canal não é um ticket do Helper.",
            "This channel is not a Helper ticket.",
        ),
        (
            "Precisas de ajuda? Abre um ticket privado.",
            "Need help? Open a private ticket.",
        ),
        ("Abrir ticket", "Open ticket"),
        ("Reabrir", "Reopen"),
        ("Fechar", "Close"),
        ("Assumir", "Claim"),
        ("Verificar", "Verify"),
        ("Participar", "Join"),
        ("Vota nesta sugestão:", "Vote on this suggestion:"),
        ("Sugestão", "Suggestion"),
        ("Sugestão publicada.", "Suggestion published."),
        ("Giveaway criado.", "Giveaway created."),
        ("Giveaway terminado.", "Giveaway ended."),
        ("Poll #", "Poll #"),
        ("Poll #{} criada.", "Poll #{} created."),
        ("Evento criado.", "Event created."),
        ("Evento atualizado.", "Event updated."),
        ("Evento cancelado.", "Event cancelled."),
        (
            "Inscreve-te primeiro com `/event-register`.",
            "Register first with `/event-register`.",
        ),
        (
            "O teu check-in já está registado.",
            "Your check-in is already recorded.",
        ),
        (
            "O teu check-in já está registado.",
            "Your check-in is already recorded.",
        ),
        (
            "Não tens uma inscrição neste evento.",
            "You are not registered for this event.",
        ),
        (
            "Não tens uma inscrição neste evento.",
            "You are not registered for this event.",
        ),
        (
            "Eventos concluídos ou cancelados não podem ser editados.",
            "Completed or cancelled events cannot be edited.",
        ),
        (
            "O evento não pode durar mais de 365 dias.",
            "The event cannot last longer than 365 days.",
        ),
        (
            "A nova data de início tem de estar no futuro.",
            "The new start date must be in the future.",
        ),
        (
            "O fim tem de ser depois do início.",
            "The end must be after the start.",
        ),
        (
            "A descrição não pode exceder 1000 caracteres.",
            "The description cannot exceed 1,000 characters.",
        ),
        (
            "A localização só pode ser alterada em eventos externos e deve ter 1–100 caracteres.",
            "Location can only be changed for external events and must be 1–100 characters.",
        ),
        (
            "O nome tem de ter entre 1 e 100 caracteres.",
            "The name must be between 1 and 100 characters.",
        ),
        (
            "O SLA deve estar entre 5 e 1440 minutos.",
            "SLA must be between 5 and 1,440 minutes.",
        ),
        (
            "A quota de painéis de tickets deste servidor foi atingida.",
            "This server has reached its ticket panel quota.",
        ),
        (
            "A lotação deve estar entre 1 e 100000.",
            "Capacity must be between 1 and 100,000.",
        ),
        (
            "A sugestão deve ter entre 3 e 1000 caracteres.",
            "The suggestion must be between 3 and 1,000 characters.",
        ),
        (
            "Pong — Vozen Helper está online.",
            "Pong — Vozen Helper is online.",
        ),
        ("Vozen Helper público:", "Public Vozen Helper:"),
        ("Setup guiado:", "Guided setup:"),
        ("Setup guardado para:", "Setup saved for:"),
        ("Próximo passo:", "Next step:"),
        ("Setup:", "Setup:"),
        ("Módulos:", "Modules:"),
        ("concluído", "complete"),
        ("pendente", "pending"),
        ("nenhum", "none"),
        ("Painel:", "Dashboard:"),
        (
            "O XP card está desativado neste servidor. Ativa-o no painel primeiro.",
            "The XP card is disabled in this server. Enable it in the dashboard first.",
        ),
        ("Plano ", "Plan "),
        (
            "Não foi possível consultar o plano agora; o Helper mantém o último snapshot seguro.",
            "Unable to check the plan right now; Helper is keeping the last safe snapshot.",
        ),
        (
            "Entitlements central ainda não estão configurados nesta instalação.",
            "Central entitlements are not configured in this installation yet.",
        ),
        (
            "Ainda não existem casos neste servidor.",
            "There are no cases in this server yet.",
        ),
        ("Não existem casos para", "There are no cases for"),
        ("Não existem casos para", "There are no cases for"),
        ("Aviso criado como caso", "Warning created as case"),
        ("Registo #", "Record #"),
        ("criado para", "created for"),
        (
            "Caso não encontrado neste servidor.",
            "Case not found in this server.",
        ),
        ("Não existem casos para", "There are no cases for"),
        ("Sem motivo", "No reason provided"),
        ("Sem conteúdo", "No content"),
        ("Sem conteúdo", "No content"),
        (
            "Não foi possível remover o timeout; confirma as permissões.",
            "Unable to remove the timeout; check permissions.",
        ),
        (
            "Não foi possível remover o ban.",
            "Unable to remove the ban.",
        ),
        (
            "Não encontrei mensagens para apagar.",
            "No messages found to delete.",
        ),
        ("Softban concluído como caso", "Softban completed as case"),
        ("Tempban concluído como caso", "Tempban completed as case"),
        ("expira em", "expires in"),
        ("Ação ", "Action "),
        ("Ação concluída como caso", "Action completed as case"),
        (
            "Não foi possível executar a ação; confirma as permissões e a hierarquia de cargos.",
            "Unable to perform the action; check permissions and role hierarchy.",
        ),
        (
            "Não tinhas AFK definido.",
            "You did not have an AFK status set.",
        ),
        ("Tag não encontrada.", "Tag not found."),
        ("Ainda não existem tags.", "There are no tags yet."),
        ("Tag `", "Tag `"),
        ("` eliminada.", "` deleted."),
        ("Ainda não existem dados de XP.", "There is no XP data yet."),
        (
            "Mensagens registadas nos últimos",
            "Messages recorded in the last",
        ),
        ("dias:", "days:"),
        (
            "Starboard configurado no canal",
            "Starboard configured in channel",
        ),
        ("Requer 3 ⭐ para publicar.", "Requires 3 ⭐ to publish."),
        ("Estado inválido:", "Invalid status:"),
        ("Sugestão #", "Suggestion #"),
        ("marcada como", "marked as"),
        (
            "Sugestão não encontrada neste servidor.",
            "Suggestion not found in this server.",
        ),
        ("Giveaway #", "Giveaway #"),
        (
            "Giveaway não encontrado, ainda ativo ou sem participantes.",
            "Giveaway not found, still active or without participants.",
        ),
        (
            "Giveaway não encontrado, ainda ativo ou sem participantes.",
            "Giveaway not found, still active or without participants.",
        ),
        (
            "Não existem giveaways ativos.",
            "There are no active giveaways.",
        ),
        ("colocado em quarantine como caso", "quarantined as case"),
        (
            "Os cargos foram guardados para restauro.",
            "Roles were saved for restoration.",
        ),
        ("Quarantine removida de", "Quarantine removed from"),
        ("cargo(s) restaurado(s).", "role(s) restored."),
        (
            "Join gate desativado; as definições guardadas podem ser reativadas.",
            "Join gate disabled; saved settings can be re-enabled.",
        ),
        ("Lockdown aplicado em", "Lockdown applied to"),
        ("canal(is) de texto.", "text channel(s)."),
        ("Motivo:", "Reason:"),
        ("Lockdown removido de", "Lockdown removed from"),
        (
            "overwrites anteriores restaurados quando estavam guardados.",
            "previous overwrites restored when they were saved.",
        ),
        ("Shadow mode ativado:", "Shadow mode enabled:"),
        ("Shadow mode desativado:", "Shadow mode disabled:"),
        (
            "respostas anti-raid/anti-nuke ficam em observação, com casos e alertas, sem contenção automática.",
            "anti-raid/anti-nuke responses are monitored with cases and alerts, without automatic containment.",
        ),
        (
            "as respostas de segurança configuradas podem aplicar contenção limitada.",
            "configured security responses may apply limited containment.",
        ),
        (
            "Anti-raid desativado; nenhuma resposta automática a bursts de joins será aplicada.",
            "Anti-raid disabled; no automatic response to join bursts will be applied.",
        ),
        ("Anti-nuke ativado:", "Anti-nuke enabled:"),
        ("ações destrutivas em", "destructive actions in"),
        (
            "ativam contenção e alerta.",
            "trigger containment and an alert.",
        ),
        (
            "Anti-nuke desativado; os eventos de Audit Log não ativam contenção automática.",
            "Anti-nuke disabled; Audit Log events do not trigger automatic containment.",
        ),
        (
            "A data de início não é RFC3339 válida.",
            "The start date is not valid RFC3339.",
        ),
        (
            "A data de fim não é RFC3339 válida.",
            "The end date is not valid RFC3339.",
        ),
        (
            "O início tem de estar no futuro.",
            "The start must be in the future.",
        ),
        (
            "A janela do evento é inválida.",
            "The event window is invalid.",
        ),
        (
            "Não existem eventos agendados neste servidor.",
            "There are no scheduled events in this server.",
        ),
        (
            "Este evento já terminou ou foi cancelado.",
            "This event has already ended or was cancelled.",
        ),
        ("O evento **", "Event **"),
        (
            "** está cheio; ficaste na lista de espera.",
            "** is full; you were added to the waitlist.",
        ),
        (
            "Inscrição confirmada para **",
            "Registration confirmed for **",
        ),
        (
            "Já estás inscrito neste evento.",
            "You are already registered for this event.",
        ),
        ("Inscrição removida;", "Registration removed;"),
        (
            "foi promovido da lista de espera.",
            "was promoted from the waitlist.",
        ),
        (
            "Inscrição removida do evento.",
            "Registration removed from the event.",
        ),
        (
            "** ainda não tem inscrições.",
            "** has no registrations yet.",
        ),
        ("inscrição(ões)", "registration(s)"),
        (
            "Não foi possível registar o check-in.",
            "Unable to record the check-in.",
        ),
        (
            "A quota de workflows deste plano foi atingida",
            "This plan's workflow quota has been reached",
        ),
        (
            "Consulta `/plan` para saber como aumentar a capacidade da guild.",
            "Check `/plan` to learn how to increase guild capacity.",
        ),
        ("Workflow #", "Workflow #"),
        (
            "É executado quando uma mensagem corresponde à condição.",
            "Runs when a message matches the condition.",
        ),
        (
            "Não existem workflows configurados.",
            "There are no workflows configured.",
        ),
        ("Dry-run: workflow", "Dry run: workflow"),
        ("não seria executado.", "would not run."),
        ("correspondeu, mas a action", "matched, but the action"),
        ("não é suportada.", "is not supported."),
        (
            "Este canal não é um ticket do Helper.",
            "This channel is not a Helper ticket.",
        ),
        ("A equipa", "The team"),
        ("aplicada", "applied"),
        ("removida", "removed"),
        ("criado", "created"),
        ("criada", "created"),
        ("publicada", "published"),
        ("encontrado", "found"),
        ("desconhecido", "unknown"),
        ("está", "is"),
        ("estão", "are"),
        ("pode", "can"),
        ("podem", "can"),
        ("deve", "must"),
        ("devem", "must"),
        ("tem de", "must"),
        ("ter de", "must"),
        ("tens", "you have"),
        ("teu", "your"),
        ("tua", "your"),
        ("foi", "was"),
        ("foram", "were"),
        ("últimos", "last"),
        ("último", "last"),
        ("mínimo", "minimum"),
        ("atualizado", "updated"),
        ("atualizada", "updated"),
        ("guardado", "saved"),
        ("guardados", "saved"),
        ("restauro", "restoration"),
        ("restaurado", "restored"),
        ("obrigatório", "required"),
        ("opções", "options"),
        ("pergunta", "question"),
        ("prémio", "prize"),
        ("vencedores", "winners"),
        ("Termina", "Ends"),
        ("Carrega", "Click"),
        ("Vota", "Vote"),
        ("registado", "recorded"),
        ("registada", "recorded"),
        ("registro", "record"),
        ("configurado", "configured"),
        ("configurada", "configured"),
        ("configura", "configure"),
        ("desativado", "disabled"),
        ("desativada", "disabled"),
        ("ativado", "enabled"),
        ("ativada", "enabled"),
        ("segurança", "security"),
        ("segurança", "security"),
        ("observação", "monitoring"),
        ("observação", "monitoring"),
        ("contenção", "containment"),
        ("contenção", "containment"),
        ("Ativa-as no painel.", "Enable them in the dashboard."),
        ("Ativa-os no painel.", "Enable them in the dashboard."),
        ("Ativa-as", "Enable them"),
        ("Ativa-os", "Enable them"),
        ("ativado", "enabled"),
        ("desativado", "disabled"),
        ("ativada", "enabled"),
        ("desativada", "disabled"),
        ("servidor", "server"),
        ("membro", "member"),
        ("membros", "members"),
        ("cargo", "role"),
        ("cargos", "roles"),
        ("permissões", "permissions"),
        ("permissões", "permissions"),
        ("hierarquia", "hierarchy"),
        ("canal", "channel"),
        ("canais", "channels"),
        ("mensagem", "message"),
        ("mensagens", "messages"),
        ("utilizador", "user"),
        ("utilizadores", "users"),
        ("razão", "reason"),
        ("razão", "reason"),
        ("equipa", "team"),
        ("histórico", "history"),
        ("histórico", "history"),
        ("resposta", "response"),
        ("respostas", "responses"),
        ("não", "not"),
        ("não", "not"),
    ];
    REPLACEMENTS
        .iter()
        .fold(input.to_owned(), |text, (from, to)| text.replace(from, to))
}

fn option_string<'a>(command: &'a CommandInteraction, name: &str) -> Option<&'a str> {
    command.data.options.iter().find_map(|option| {
        (option.name == name).then_some(match &option.value {
            CommandDataOptionValue::String(value) => value.as_str(),
            _ => return None,
        })
    })
}

fn parse_embed_colour(value: &str) -> Option<Colour> {
    let hex = value.strip_prefix('#').unwrap_or(value);
    (hex.len() == 6 && hex.chars().all(|character| character.is_ascii_hexdigit()))
        .then(|| u32::from_str_radix(hex, 16).ok())
        .flatten()
        .map(Colour::new)
}

fn option_i64(command: &CommandInteraction, name: &str) -> Option<i64> {
    command.data.options.iter().find_map(|option| {
        (option.name == name).then_some(match option.value {
            CommandDataOptionValue::Integer(value) => value,
            _ => return None,
        })
    })
}

fn option_bool(command: &CommandInteraction, name: &str) -> Option<bool> {
    command.data.options.iter().find_map(|option| {
        (option.name == name).then_some(match option.value {
            CommandDataOptionValue::Boolean(value) => value,
            _ => return None,
        })
    })
}

fn option_role(command: &CommandInteraction, name: &str) -> Option<RoleId> {
    command.data.options.iter().find_map(|option| {
        (option.name == name).then_some(match option.value {
            CommandDataOptionValue::Role(role) => role,
            _ => return None,
        })
    })
}

fn truncate(value: &str, max_chars: usize) -> String {
    let mut output = value.chars().take(max_chars).collect::<String>();
    if value.chars().count() > max_chars {
        output.push('…');
    }
    output
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedCustomCommand {
    name: String,
    args: String,
}

#[cfg(test)]
fn parse_custom_command(content: &str, prefix: &str) -> Option<ParsedCustomCommand> {
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
    Some(ParsedCustomCommand {
        name,
        args: parts
            .next()
            .unwrap_or_default()
            .trim()
            .chars()
            .take(512)
            .collect(),
    })
}

#[cfg(test)]
fn custom_command_channel_ignored(raw_channels: Option<String>, channel_id: ChannelId) -> bool {
    raw_channels.is_some_and(|channels| {
        channels
            .split(',')
            .map(str::trim)
            .any(|candidate| candidate == channel_id.to_string())
    })
}

fn custom_command_is_staff(permissions: Option<Permissions>) -> bool {
    permissions.is_some_and(|permissions| {
        permissions.contains(Permissions::ADMINISTRATOR)
            || permissions.contains(Permissions::MANAGE_GUILD)
    })
}

#[cfg(test)]
fn render_custom_command(
    template: &str,
    user_id: serenity::all::UserId,
    channel_id: ChannelId,
    server_name: &str,
    args: &str,
    max_chars: usize,
) -> String {
    let rendered = template
        .replace("{user}", &format!("<@{}>", user_id))
        .replace("{channel}", &format!("<#{}>", channel_id))
        .replace("{server}", server_name)
        .replace("{args}", args)
        .replace("@everyone", "@\u{200b}everyone")
        .replace("@here", "@\u{200b}here");
    rendered.chars().take(max_chars.clamp(1, 2_000)).collect()
}

fn account_age_days(now_timestamp: i64, created_timestamp: i64) -> i64 {
    ((now_timestamp - created_timestamp) / 86_400).max(0)
}

fn is_destructive_audit_action(action: serenity::model::guild::audit_log::Action) -> bool {
    matches!(
        action,
        serenity::model::guild::audit_log::Action::Channel(
            serenity::model::guild::audit_log::ChannelAction::Delete,
        ) | serenity::model::guild::audit_log::Action::ChannelOverwrite(
            serenity::model::guild::audit_log::ChannelOverwriteAction::Delete,
        ) | serenity::model::guild::audit_log::Action::Role(
            serenity::model::guild::audit_log::RoleAction::Delete,
        ) | serenity::model::guild::audit_log::Action::Webhook(
            serenity::model::guild::audit_log::WebhookAction::Delete,
        ) | serenity::model::guild::audit_log::Action::Member(
            serenity::model::guild::audit_log::MemberAction::BanAdd,
        ) | serenity::model::guild::audit_log::Action::Member(
            serenity::model::guild::audit_log::MemberAction::Kick,
        )
    )
}

fn join_burst_armed(
    joins: &mut HashMap<String, VecDeque<Instant>>,
    guild_id: &str,
    now: Instant,
    window: Duration,
    threshold: usize,
) -> bool {
    join_burst_count(joins, guild_id, now, window, threshold) >= threshold.max(2)
}

/// Record one join and return the bounded burst size used by the pure
/// anti-raid evaluator.  Reaching the threshold consumes the current burst so
/// a single incident cannot trigger repeatedly for every following member.
fn join_burst_count(
    joins: &mut HashMap<String, VecDeque<Instant>>,
    guild_id: &str,
    now: Instant,
    window: Duration,
    threshold: usize,
) -> usize {
    let window = window.max(Duration::from_secs(1));
    let threshold = threshold.max(2);
    let entries = joins.entry(guild_id.to_owned()).or_default();
    while entries
        .front()
        .is_some_and(|joined_at| now.duration_since(*joined_at) > window)
    {
        entries.pop_front();
    }
    entries.push_back(now);
    let count = entries.len();
    if count >= threshold {
        entries.clear();
    }
    count
}

async fn finish_giveaway(
    http: &serenity::http::Http,
    store: &Store,
    guild_id: &str,
    id: i64,
) -> Result<bool> {
    let update_lock = giveaway_display::update_lock(id);
    let _update = update_lock.lock().await;
    let Some(giveaway) = store.giveaway(id)? else {
        return Ok(false);
    };
    if giveaway.guild_id != guild_id {
        return Ok(false);
    }
    let Some((winners, claim_at)) = store.prepare_giveaway_result(guild_id, id)? else {
        return Ok(false);
    };
    let content = giveaway_display::Content {
        giveaway: &giveaway,
        winners: Some(&winners),
        rerolled: false,
        participants: store.giveaway_participant_count(id)?,
    };
    let channel_id = giveaway
        .channel_id
        .parse::<u64>()
        .map(ChannelId::new)
        .map_err(|_| anyhow::anyhow!("invalid giveaway channel"))?;
    let published = giveaway_display::publish(http, channel_id, None, &content, true).await;
    if let Err(error) = published {
        store.release_giveaway_claim(id, claim_at)?;
        return Err(error.into());
    }
    store.mark_giveaway_announced(id, claim_at)?;
    // The public announcement is the recorded outcome. A missing or uneditable
    // original panel does not cause another draw.
    if let Some(message_id) = giveaway
        .message_id
        .as_deref()
        .and_then(|raw| raw.parse::<u64>().ok())
        && let Err(error) = giveaway_display::publish(
            http,
            channel_id,
            Some(MessageId::new(message_id)),
            &content,
            false,
        )
        .await
    {
        warn!(giveaway_id = id, %error, "could not close giveaway panel after announcement");
    }
    Ok(true)
}

async fn reroll_giveaway(
    http: &serenity::http::Http,
    store: &Store,
    guild_id: &str,
    id: i64,
) -> Result<Option<String>> {
    let Some(giveaway) = store.giveaway(id)? else {
        return Ok(None);
    };
    if giveaway.guild_id != guild_id || !giveaway.ended {
        return Ok(None);
    }
    let mut entries = store.giveaway_entries(id)?;
    if entries.is_empty() {
        return Ok(None);
    }
    entries.shuffle(&mut rand::rng());
    let winner = entries[0].clone();
    let channel = giveaway.channel_id.parse::<u64>().map(ChannelId::new)?;
    giveaway_display::publish(
        http,
        channel,
        None,
        &giveaway_display::Content {
            giveaway: &giveaway,
            winners: Some(std::slice::from_ref(&winner)),
            rerolled: true,
            participants: entries.len() as u64,
        },
        true,
    )
    .await?;
    Ok(Some(winner))
}

async fn restore_quarantine_roles<F, Fut>(
    store: &Store,
    guild_id: &str,
    user_id: &str,
    role_ids: &[String],
    reason: &str,
    mut restore: F,
) -> Result<(usize, usize)>
where
    F: FnMut(RoleId) -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let mut pending = Vec::new();
    for raw_role in role_ids {
        let restored = match raw_role.parse::<u64>().ok().filter(|id| *id != 0) {
            Some(id) => restore(RoleId::new(id)).await,
            None => false,
        };
        if !restored {
            pending.push(raw_role.clone());
        }
    }
    if pending.is_empty() {
        store.clear_quarantine(guild_id, user_id)?;
    } else {
        store.save_quarantine(guild_id, user_id, &pending, reason)?;
    }
    Ok((role_ids.len() - pending.len(), pending.len()))
}

fn poll_open_message(id: i64, question: &str, options: &[String], end_at: i64) -> CreateMessage {
    let labels = options
        .iter()
        .enumerate()
        .map(|(index, value)| {
            CreateButton::new(format!("poll:{id}:{index}"))
                .label(format!("{}: {}", index + 1, truncate(value, 70)))
                .style(ButtonStyle::Secondary)
        })
        .collect::<Vec<_>>();
    CreateMessage::new()
        .content(format!(
            "🗳️ **Poll #{id}: {question}**\n{}\nEnds <t:{}:R>",
            options
                .iter()
                .enumerate()
                .map(|(i, v)| format!("{}️⃣ {}", i + 1, v))
                .collect::<Vec<_>>()
                .join("\n"),
            end_at / 1_000
        ))
        .allowed_mentions(CreateAllowedMentions::new())
        .components(vec![CreateActionRow::Buttons(labels)])
}

fn poll_result_message(poll: &helper_store::PollRecord, counts: &[i64]) -> EditMessage {
    let results = poll
        .options
        .iter()
        .enumerate()
        .map(|(index, option)| {
            format!(
                "{}️⃣ {} — {} voto(s)",
                index + 1,
                option,
                counts.get(index).copied().unwrap_or_default()
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    EditMessage::new()
        .content(format!(
            "🗳️ **Poll #{} encerrada: {}**\n{}",
            poll.id, poll.question, results
        ))
        .allowed_mentions(CreateAllowedMentions::new())
        .components(Vec::new())
}

async fn finish_poll(
    http: &serenity::http::Http,
    store: &Store,
    guild_id: &str,
    id: i64,
) -> Result<bool> {
    let Some(poll) = store.poll(id)? else {
        return Ok(false);
    };
    if poll.guild_id != guild_id {
        return Ok(false);
    }
    // Freeze votes first. A failed edit must leave the closing job retryable;
    // retrying a closed poll edits the same message with the frozen counts.
    if !poll.closed {
        store.close_poll(id)?;
    }
    let counts = store.poll_counts(id, poll.options.len())?;
    let message_id = poll
        .message_id
        .as_deref()
        .and_then(|raw| raw.parse::<u64>().ok())
        .filter(|id| *id != 0)
        .ok_or_else(|| anyhow::anyhow!("poll panel message is missing or invalid"))?;
    let channel = poll
        .channel_id
        .parse::<u64>()
        .ok()
        .filter(|id| *id != 0)
        .ok_or_else(|| anyhow::anyhow!("poll channel is invalid"))?;
    ChannelId::new(channel)
        .edit_message(
            http,
            MessageId::new(message_id),
            poll_result_message(&poll, &counts),
        )
        .await?;
    Ok(true)
}

fn lockdown_overwrite(
    everyone: RoleId,
    existing: Option<&PermissionOverwrite>,
) -> PermissionOverwrite {
    PermissionOverwrite {
        allow: existing.map_or(Permissions::empty(), |value| value.allow)
            - Permissions::SEND_MESSAGES,
        deny: existing.map_or(Permissions::empty(), |value| value.deny)
            | Permissions::SEND_MESSAGES,
        kind: PermissionOverwriteType::Role(everyone),
    }
}

async fn apply_lockdown(
    http: &serenity::http::Http,
    store: &Store,
    guild_id: serenity::all::GuildId,
    enabled: bool,
) -> Result<usize> {
    let channels = http.get_channels(guild_id).await?;
    let everyone = RoleId::new(guild_id.get());
    let mut changed = 0;
    for channel in channels
        .into_iter()
        .filter(|channel| matches!(channel.kind, ChannelType::Text | ChannelType::News))
    {
        let key = format!("security.lockdown.previous.{}", channel.id);
        if enabled {
            if store.get_setting(&guild_id.to_string(), &key)?.is_none() {
                if let Some(existing) = channel.permission_overwrites.iter().find(|overwrite| {
                    matches!(overwrite.kind, PermissionOverwriteType::Role(role) if role == everyone)
                }) {
                    store.set_setting(
                        &guild_id.to_string(),
                        &key,
                        &serde_json::to_string(existing)?,
                    )?;
                } else {
                    store.set_setting(&guild_id.to_string(), &key, "")?;
                }
            }
            let existing = channel
                .permission_overwrites
                .iter()
                .find(|overwrite| overwrite.kind == PermissionOverwriteType::Role(everyone));
            channel
                .create_permission(http, lockdown_overwrite(everyone, existing))
                .await?;
            changed += 1;
        } else if let Some(previous) = store.get_setting(&guild_id.to_string(), &key)? {
            if previous.is_empty() {
                channel
                    .delete_permission(http, PermissionOverwriteType::Role(everyone))
                    .await?;
            } else {
                let overwrite = serde_json::from_str::<PermissionOverwrite>(&previous)?;
                channel.create_permission(http, overwrite).await?;
            }
            store.delete_setting(&guild_id.to_string(), &key)?;
            changed += 1;
        }
    }
    store.set_setting(
        &guild_id.to_string(),
        "security.lockdown.active",
        if enabled { "true" } else { "false" },
    )?;
    Ok(changed)
}

fn required_permission(command: &str) -> Option<Permissions> {
    match command {
        "warn" | "violation" | "timeout" | "untimeout" | "note" | "reason" | "quarantine"
        | "unquarantine" | "modlogs" | "cases" => Some(Permissions::MODERATE_MEMBERS),
        "kick" => Some(Permissions::KICK_MEMBERS),
        "ban" | "unban" | "tempban" | "softban" => Some(Permissions::BAN_MEMBERS),
        "purge" => Some(Permissions::MANAGE_MESSAGES),
        "ticket-panel" | "ticket-config" | "ticket-update" => Some(Permissions::MANAGE_CHANNELS),
        "slowmode" | "lockdown" | "unlock" => Some(Permissions::MANAGE_CHANNELS),
        "setup" | "verify-panel" | "language" => Some(Permissions::MANAGE_GUILD),
        "rolepanel" => Some(Permissions::MANAGE_ROLES),
        "join-gate" => Some(Permissions::MANAGE_ROLES),
        "anti-raid" => Some(Permissions::MANAGE_GUILD),
        "security-mode" => Some(Permissions::MANAGE_GUILD),
        "anti-nuke" => Some(Permissions::MANAGE_GUILD),
        "event-create" | "event-edit" | "event-cancel" | "event-attendees" => {
            Some(Permissions::CREATE_EVENTS)
        }
        "invites" => Some(Permissions::MANAGE_GUILD),
        "temp-channel" => Some(Permissions::MANAGE_CHANNELS),
        "embed" => Some(Permissions::MANAGE_MESSAGES),
        "tag-set" | "tag-delete" | "giveaway-start" | "giveaway-end" | "gstart" | "gend"
        | "greroll" | "starboard-set" | "workflow-create" | "workflow-dry-run"
        | "workflow-toggle" | "workflow-delete" => Some(Permissions::MANAGE_GUILD),
        "suggestion" => Some(Permissions::MANAGE_MESSAGES),
        _ => None,
    }
}

/// The Helper never derives its language from Discord or browser settings.
/// A server starts in English until an administrator explicitly selects one of
/// the locales supported by the Vozen site.
const DEFAULT_HELPER_LOCALE: &str = "en";
const HELPER_LANGUAGE_SETTING: &str = "core.language";
const HELPER_LOCALES: &[(&str, &str)] = &[
    ("en", "English"),
    ("pt", "Português"),
    ("fr", "Français"),
    ("es", "Español"),
    ("de", "Deutsch"),
    ("tr", "Türkçe"),
    ("ar", "العربية"),
    ("zh", "繁體中文"),
    ("ru", "Русский"),
    ("ko", "한국어"),
];

fn helper_locale(locale: &str) -> Option<(&'static str, &'static str)> {
    HELPER_LOCALES
        .iter()
        .copied()
        .find(|(code, _)| *code == locale)
}

fn helper_locale_for_guild(store: &Store, guild_id: &str) -> Result<&'static str> {
    Ok(store
        .get_setting(guild_id, HELPER_LANGUAGE_SETTING)?
        .as_deref()
        .and_then(|locale| helper_locale(locale).map(|(code, _)| code))
        .unwrap_or(DEFAULT_HELPER_LOCALE))
}

fn parse_duration(raw: &str) -> Option<i64> {
    let value = raw.trim();
    let (number, unit) = value.split_at_checked(value.len().checked_sub(1)?)?;
    let amount = number.parse::<i64>().ok()?.checked_mul(match unit {
        "s" => 1_000,
        "m" => 60_000,
        "h" => 3_600_000,
        "d" => 86_400_000,
        _ => return None,
    })?;
    (amount > 0 && amount <= 365 * 86_400_000).then_some(amount)
}

fn parse_clock_time(raw: &str) -> Option<(u32, u32)> {
    let (hour, minute) = raw.trim().split_once(':')?;
    if hour.len() != 2 || minute.len() != 2 {
        return None;
    }
    let hour = hour.parse::<u32>().ok()?;
    let minute = minute.parse::<u32>().ok()?;
    (hour < 24 && minute < 60).then_some((hour, minute))
}

/// Return the delay until a reminder expression. Durations retain their
/// existing semantics; `HH:MM` is interpreted in the server's configured
/// fixed UTC offset and resolves to the next occurrence of that local time.
fn parse_reminder_delay(raw: &str, timezone: &str, now_ms: i64) -> Option<i64> {
    if let Some(delay) = parse_duration(raw) {
        return Some(delay);
    }
    let (hour, minute) = parse_clock_time(raw)?;
    let offset = parse_utc_offset_minutes(timezone)?;
    let now = Utc.timestamp_millis_opt(now_ms).single()?;
    let local_now = (now + ChronoDuration::minutes(i64::from(offset))).naive_utc();
    let target = local_now.date().and_hms_opt(hour, minute, 0)?;
    let mut delay = target - local_now;
    if delay <= ChronoDuration::zero() {
        delay += ChronoDuration::days(1);
    }
    let milliseconds = delay.num_milliseconds();
    (milliseconds > 0).then_some(milliseconds)
}

fn format_duration(milliseconds: i64) -> String {
    let units = [
        (86_400_000, "d"),
        (3_600_000, "h"),
        (60_000, "m"),
        (1_000, "s"),
    ];
    for (unit_ms, suffix) in units {
        if milliseconds % unit_ms == 0 {
            return format!("{}{}", milliseconds / unit_ms, suffix);
        }
    }
    format!("{}ms", milliseconds)
}

fn shadow_mode_enabled(raw: Option<&str>) -> bool {
    raw.is_some_and(|value| value.eq_ignore_ascii_case("true"))
}

fn anti_nuke_containment_deadline(now_seconds: i64, incident_minutes: u64) -> i64 {
    now_seconds + i64::try_from(incident_minutes.clamp(1, 120)).unwrap_or(120) * 60
}

/// Capture a bounded baseline for invite attribution before member events are
/// processed. Discord does not include an invite code in
/// `guild_member_addition`, therefore a missing baseline would make the first
/// join after a restart impossible to attribute safely.
async fn refresh_invite_snapshots(
    http: &Arc<serenity::http::Http>,
    store: &Store,
    guild_id: serenity::all::GuildId,
) {
    let guild_text = guild_id.to_string();
    if !feature_enabled(store, &guild_text, "management.invite_tracker", None) {
        return;
    }

    let invites = match guild_id.invites(http).await {
        Ok(invites) => invites,
        Err(error) => {
            warn!(%guild_text, %error, "failed to prime invite tracker snapshots");
            return;
        }
    };

    let mut observed = 0usize;
    for invite in invites.into_iter().take(200) {
        let inviter_id = invite.inviter.as_ref().map(|user| user.id.to_string());
        if store
            .observe_invite(
                &guild_text,
                &invite.code,
                invite.uses.min(9_999_999) as i64,
                inviter_id.as_deref(),
            )
            .is_ok()
        {
            observed += 1;
        }
    }
    info!(%guild_text, observed, "invite tracker snapshots primed");
}

fn feature_enabled(store: &Store, guild_id: &str, key: &str, legacy_key: Option<&str>) -> bool {
    if key == "support.welcome" {
        return store
            .welcome_configuration(guild_id)
            .map(|value| value.0)
            .unwrap_or(false);
    }
    // A legacy or manually inserted setting must not bypass the canonical
    // lifecycle.  In particular, provider features marked blocked stay off
    // until their official credentials/approvals are available.
    if !feature_maturity_allows_runtime(key) {
        return false;
    }
    // `feature_settings` is the revisioned source of truth.  Compatibility
    // projections in `settings` can be stale during a rolling deploy and must
    // never re-enable a feature that the owner explicitly disabled.
    if let Ok(Some(record)) = store.get_feature_setting(guild_id, key) {
        return record.enabled;
    }
    store
        .get_setting(guild_id, &format!("feature.{key}"))
        .ok()
        .flatten()
        .and_then(|value| value.parse::<bool>().ok())
        .or_else(|| {
            legacy_key.and_then(|legacy| {
                store
                    .get_setting(guild_id, legacy)
                    .ok()
                    .flatten()
                    .and_then(|value| value.parse::<bool>().ok())
            })
        })
        .unwrap_or(false)
}

fn instagram_access_allowed(approved: bool, development_mode: bool) -> bool {
    approved || development_mode
}

fn instagram_runtime_allowed() -> bool {
    let approved = first_env_flag_is_true(&["META_APP_APPROVED", "META_INSTAGRAM_APP_APPROVED"]);
    let development_mode = env_flag_is_true("META_INSTAGRAM_DEVELOPMENT_MODE");
    instagram_access_allowed(approved, development_mode)
}

fn feature_maturity_allows_runtime(key: &str) -> bool {
    let configured = |name: &str| {
        std::env::var(name)
            .ok()
            .is_some_and(|value| !value.trim().is_empty())
    };
    let any_configured = |names: &[&str]| names.iter().any(|name| configured(name));
    let approved = |names: &[&str]| first_env_flag_is_true(names);
    // `feature_is_configurable` answers whether the panel can show a setup
    // page. It must not override a globally blocked provider: a stale or
    // hand-written setting is never permission to run without the official
    // credential/approval gate.
    match (feature_maturity(key), key) {
        // Beta integrations are still real runtime adapters, but they must
        // not be activated from a stale/manual guild setting while the
        // process lacks the same credentials/endpoints used by their
        // workers.  The API performs the equivalent client health check;
        // keeping this guard in the gateway prevents a rolling deploy from
        // briefly reporting a non-functional feature as enabled.
        (helper_contracts::FeatureMaturity::Beta, "social.youtube") => {
            configured("YOUTUBE_API_KEY")
        }
        (helper_contracts::FeatureMaturity::Beta, "social.twitch") => {
            configured("TWITCH_CLIENT_ID")
                && configured("TWITCH_CLIENT_SECRET")
                && configured("TWITCH_EVENTSUB_SECRET")
                && configured("TWITCH_EVENTSUB_CALLBACK_URL")
        }
        (helper_contracts::FeatureMaturity::Beta, "web3.gas_tracker") => any_configured(&[
            "ETHEREUM_RPC_URL",
            "POLYGON_RPC_URL",
            "ARBITRUM_RPC_URL",
            "BASE_RPC_URL",
        ]),
        // RSS and podcasts use public HTTP feeds and the worker's SSRF
        // checks; there is no provider secret to require here.
        (helper_contracts::FeatureMaturity::Beta, "social.rss") => true,
        (helper_contracts::FeatureMaturity::Blocked, "social.tiktok") => tiktok_runtime_allowed(
            approved(&["TIKTOK_APP_APPROVED", "TIKTOK_DISPLAY_API_APPROVED"]),
            env_flag_is_true("TIKTOK_SANDBOX_MODE"),
            TikTokOAuthClient::from_env().is_some(),
            TikTokClient::from_env().is_some(),
        ),
        (helper_contracts::FeatureMaturity::Blocked, "social.instagram") => {
            instagram_runtime_allowed()
                && configured("META_INSTAGRAM_ACCESS_TOKEN")
                && configured("META_INSTAGRAM_USER_ID")
        }
        (helper_contracts::FeatureMaturity::Blocked, "social.kick") => {
            approved(&["KICK_APP_APPROVED", "KICK_API_APPROVED"]) && configured("KICK_ACCESS_TOKEN")
        }
        (helper_contracts::FeatureMaturity::Blocked, "growth.monetization") => {
            approved(&["STRIPE_CONNECT_APPROVED"])
                && configured("STRIPE_SECRET_KEY")
                && configured("STRIPE_WEBHOOK_SECRET")
        }
        (helper_contracts::FeatureMaturity::Blocked, "web3.gating") => {
            configured("SIWE_DOMAIN")
                && configured("SIWE_URI")
                && configured("SIWE_SESSION_SECRET")
                && configured("SIWE_ALLOWED_CONTRACTS")
        }
        (helper_contracts::FeatureMaturity::Blocked, _) => false,
        _ => feature_is_configurable(key),
    }
}

fn feature_explicitly_disabled(store: &Store, guild_id: &str, key: &str) -> bool {
    store
        .get_feature_setting(guild_id, key)
        .ok()
        .flatten()
        .map(|value| !value.enabled)
        .or_else(|| {
            store
                .get_setting(guild_id, &format!("feature.{key}"))
                .ok()
                .flatten()
                .and_then(|value| value.parse::<bool>().ok().map(|enabled| !enabled))
        })
        .unwrap_or(false)
}

fn is_moderation_command(name: &str) -> bool {
    matches!(
        name,
        "warn"
            | "violation"
            | "note"
            | "reason"
            | "kick"
            | "ban"
            | "timeout"
            | "tempban"
            | "softban"
            | "untimeout"
            | "unban"
            | "purge"
            | "quarantine"
            | "unquarantine"
            | "slowmode"
            | "lockdown"
            | "unlock"
    )
}

/// Keep command availability tied to the same revisioned feature switch that
/// drives gateway handlers and provider workers.  Previously only a handful
/// of commands checked their toggle, which meant a dashboard owner could
/// disable a module while its slash commands continued to mutate state.
fn format_youtube_search_results(results: &[YouTubeSearchResult]) -> String {
    results
        .iter()
        .enumerate()
        .map(|(index, result)| {
            format!(
                "{}. **{}** — {}\n{}",
                index + 1,
                sanitize_external_text(&truncate(&result.title, 160)),
                sanitize_external_text(&truncate(&result.channel_title, 80)),
                result.url
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn format_twitch_search_results(results: &[TwitchChannelSearchResult]) -> String {
    results
        .iter()
        .enumerate()
        .map(|(index, result)| {
            let status = if result.is_live { "LIVE" } else { "offline" };
            let details = if result.game_name.is_empty() {
                status.to_string()
            } else {
                format!("{status} · {}", truncate(&result.game_name, 80))
            };
            format!(
                "{}. **{}** — {}\n{} ({})",
                index + 1,
                sanitize_external_text(&truncate(&result.display_name, 100)),
                sanitize_external_text(&truncate(&result.title, 160)),
                result.url,
                sanitize_external_text(&details)
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn sanitize_external_text(value: &str) -> String {
    value
        .replace("@everyone", "@\u{200b}everyone")
        .replace("@here", "@\u{200b}here")
}

fn command_feature_key(name: &str) -> Option<&'static str> {
    Some(match name {
        "privacy" => "management.privacy",
        "join-gate" => "protection.join_gate",
        "anti-raid" => "protection.anti_raid",
        "anti-nuke" | "security-mode" => "management.audit",
        "modlogs" | "warn" | "violation" | "note" | "reason" | "kick" | "ban" | "timeout"
        | "tempban" | "softban" | "untimeout" | "unban" | "purge" | "quarantine"
        | "unquarantine" | "slowmode" | "lockdown" | "unlock" => "management.moderation",
        "afk" | "remind" => "utility.reminders",
        "tag" | "tags" | "tag-set" | "tag-delete" => "management.custom_commands",
        "rank" => "studio.rank_card",
        "leaderboard" | "leaderboard-privacy" => "community.leaderboard",
        "achievements" => "community.achievements",
        "serverstats" => "insights.stats",
        "crypto" => "web3.crypto_queries",
        "gas" => "web3.gas_tracker",
        "search" => "utility.search",
        "emojis" => "utility.emojis",
        "invites" => "management.invite_tracker",
        "balance" | "daily" | "work" | "economy-top" => "community.economy",
        "temp-channel" => "utility.temp_channels",
        "embed" => "utility.embeds",
        "starboard-set" => "community.starboard",
        "suggest" | "suggestion" => "community.suggestions",
        "giveaway-start" | "giveaway-end" | "giveaway-list" | "gstart" | "gend" | "glist"
        | "greroll" => "community.giveaways",
        "poll" => "management.polls",
        "workflow-create" | "workflow-list" | "workflow-dry-run" | "workflow-toggle"
        | "workflow-delete" => "management.workflows",
        "event-create" | "event-edit" | "event-cancel" | "event-list" | "event-register"
        | "event-unregister" | "event-attendees" | "event-checkin" => "community.events",
        "birthday-set" | "birthday-remove" => "community.birthdays",
        "rolepanel" => "community.role_panels",
        "verify-panel" => "protection.join_gate",
        "ticket-panel" | "ticket-config" | "ticket-rate" | "ticket-update" => "support.tickets",
        "help" => "utility.help",
        _ => return None,
    })
}

fn feature_title(key: &str) -> &'static str {
    match key {
        "protection.join_gate" => "Join gate",
        "protection.anti_raid" => "Anti-raid",
        "management.audit" => "Audit and permissions",
        "management.privacy" => "Privacy",
        "management.moderation" => "Moderation",
        "utility.reminders" => "Reminders",
        "management.custom_commands" => "Custom commands",
        "studio.rank_card" => "XP card",
        "community.leaderboard" => "Leaderboard",
        "community.achievements" => "Achievements",
        "insights.stats" => "Server statistics",
        "web3.crypto_queries" => "Crypto queries",
        "web3.gas_tracker" => "Gas tracker",
        "utility.search" => "Search",
        "utility.emojis" => "Emojis",
        "management.invite_tracker" => "Invite tracker",
        "community.economy" => "Economy",
        "utility.temp_channels" => "Temporary channels",
        "utility.embeds" => "Embeds",
        "community.starboard" => "Starboard",
        "community.suggestions" => "Suggestions",
        "community.giveaways" => "Giveaways",
        "management.polls" => "Polls",
        "management.workflows" => "Workflows",
        "community.events" => "Events",
        "community.birthdays" => "Birthdays",
        "community.role_panels" => "Role panels",
        "support.tickets" => "Tickets",
        "utility.help" => "Help",
        _ => "this feature",
    }
}

fn scheduled_action_feature(action_type: &str) -> Option<&'static str> {
    match action_type {
        // Releasing a temporary sanction must survive a feature disable.
        "unban" => None,
        "giveaway_end" => Some("community.giveaways"),
        "poll_end" => Some("management.polls"),
        "ticket_sla" => Some("support.tickets"),
        "event_reminder" => Some("community.events"),
        _ => None,
    }
}

fn should_clear_anti_spam_timeout(
    expected_until_unix: i64,
    current_until_unix: Option<i64>,
    now_unix: i64,
) -> bool {
    let Some(current_until_unix) = current_until_unix else {
        return false;
    };

    // Discord may round the RFC3339 value to whole seconds. Only clear the
    // timeout we created; a later moderator timeout must remain untouched.
    now_unix >= expected_until_unix && current_until_unix.abs_diff(expected_until_unix) <= 2
}

fn should_cleanup_temp_channel(new_channel_id: Option<serenity::all::ChannelId>) -> bool {
    // A move is not an abandonment. Without the optional Serenity cache we
    // cannot safely inspect the remaining occupants, so defer cleanup until
    // the owner fully disconnects from voice.
    new_channel_id.is_none()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct JoinGateVerificationDecision {
    assign_verified_role: bool,
    remove_quarantine_role: bool,
    already_verified: bool,
}

/// A verification panel promotes a member to the configured verified role and
/// removes the distinct quarantine role, if it is still present. The role IDs
/// are read from the current server configuration rather than trusted from an
/// old button payload, so stale panels cannot grant a changed role.
fn evaluate_join_gate_verification(
    member_roles: &[RoleId],
    quarantine_role: Option<RoleId>,
    verified_role: RoleId,
) -> JoinGateVerificationDecision {
    let already_verified = member_roles.contains(&verified_role);
    let remove_quarantine_role = quarantine_role
        .filter(|role| *role != verified_role)
        .is_some_and(|role| member_roles.contains(&role));
    JoinGateVerificationDecision {
        assign_verified_role: !already_verified,
        remove_quarantine_role,
        already_verified,
    }
}

fn setting_string(store: &Store, guild_id: &str, key: &str) -> Option<String> {
    store.get_setting(guild_id, key).ok().flatten()
}

fn welcome_guide_button(
    guild: &str,
    step: &str,
    config: &serde_json::Value,
) -> Option<CreateButton> {
    let guild = guild.parse::<u64>().ok().filter(|id| *id > 0)?;
    if step == "help" {
        return Some(
            CreateButton::new(format!("welcome:step:{guild}:help"))
                .label("Get help")
                .emoji(ReactionType::Unicode("❓".into()))
                .style(ButtonStyle::Secondary),
        );
    }
    let (field, label, emoji) = match step {
        "rules" => ("rulesChannel", "Read the rules", "📜"),
        "introductions" => ("introductionsChannel", "Introduce yourself", "👋"),
        "channels" => ("channelsChannel", "Explore channels", "🧭"),
        _ => return None,
    };
    let channel = config[field]
        .as_str()?
        .parse::<u64>()
        .ok()
        .filter(|id| *id > 0)?;
    Some(
        CreateButton::new_link(format!("https://discord.com/channels/{guild}/{channel}"))
            .label(label)
            .emoji(ReactionType::Unicode(emoji.to_string())),
    )
}

/// Resolve a reusable Studio template without allowing arbitrary JSON to leak
/// into Discord. Templates are opt-in through the templates feature and only
/// bounded string fields are accepted. Missing or malformed templates fall
/// back to the feature's own configured message.
fn unified_welcome_text(
    store: &Store,
    guild: &str,
    config: &serde_json::Value,
    slot: &str,
    fallback: &str,
) -> String {
    let field = match slot {
        "dm" => "dmMessage",
        "farewell" => "farewellMessage",
        _ => "message",
    };
    let fallback = config[field].as_str().unwrap_or(fallback).to_string();
    if !feature_enabled(store, guild, "management.templates", None)
        || !setting_bool(store, guild, "management.templates.enabled", true)
    {
        return fallback;
    }
    let Some(id) = config["templateId"].as_str().filter(|id| !id.is_empty()) else {
        return fallback;
    };
    let template = store
        .get_setting(guild, &format!("studio.template.{id}"))
        .ok()
        .flatten()
        .and_then(|raw| serde_json::from_str::<serde_json::Value>(&raw).ok());
    let Some(template) = template else {
        return fallback;
    };
    let fallback = if slot == "welcome" {
        render_bounded_template_message(&template, "welcomeChannel", &fallback)
    } else {
        fallback
    };
    render_bounded_template_message(&template, slot, &fallback)
}

fn ticket_opening_message(
    opener_id: serenity::all::UserId,
    staff_role_id: Option<RoleId>,
) -> String {
    match staff_role_id {
        Some(role_id) => format!(
            "Hello <@{opener_id}>! I've called <@&{role_id}> to help you.\nTell us what you need and the support team will reply here."
        ),
        None => format!("Hello <@{opener_id}>! Tell us what you need."),
    }
}

fn ticket_opening_mentions(
    opener_id: serenity::all::UserId,
    staff_role_id: Option<RoleId>,
) -> CreateAllowedMentions {
    CreateAllowedMentions::new()
        .everyone(false)
        .all_roles(false)
        .all_users(false)
        .users([opener_id])
        .roles(staff_role_id)
        .replied_user(false)
}

fn ticket_member_is_staff(
    configured_role_id: Option<RoleId>,
    member_roles: &[RoleId],
    permissions: Permissions,
    is_guild_owner: bool,
) -> bool {
    configured_role_id.is_some_and(|role_id| member_roles.contains(&role_id))
        || is_guild_owner
        || permissions.contains(Permissions::MANAGE_CHANNELS)
        || permissions.contains(Permissions::ADMINISTRATOR)
}

/// Resolved interaction permissions include channel overwrites. A negative
/// result must not fall back to broader guild-level permissions.
async fn ticket_actor_is_staff(
    ctx: &Context,
    guild_id: serenity::all::GuildId,
    channel_id: ChannelId,
    user_id: serenity::all::UserId,
    interaction_member: Option<&serenity::all::Member>,
    configured_role_id: Option<RoleId>,
) -> bool {
    if let Some(member) = interaction_member
        && let Some(permissions) = member.permissions
    {
        return ticket_member_is_staff(configured_role_id, &member.roles, permissions, false);
    }

    let (member, guild) = tokio::join!(
        guild_id.member(&ctx.http, user_id),
        guild_id.to_partial_guild(&ctx.http),
    );
    let Ok(member) = member else {
        return false;
    };
    if configured_role_id.is_some_and(|role_id| member.roles.contains(&role_id)) {
        return true;
    }
    let Ok(guild) = guild else {
        return false;
    };
    let Ok(serenity::all::Channel::Guild(channel)) = channel_id.to_channel(&ctx.http).await else {
        return false;
    };
    if channel.guild_id != guild_id {
        return false;
    }
    let permissions = guild.user_permissions_in(&channel, &member);
    ticket_member_is_staff(
        configured_role_id,
        &member.roles,
        permissions,
        guild.owner_id == user_id,
    )
}

fn setting_u64(store: &Store, guild_id: &str, key: &str, default: u64) -> u64 {
    setting_string(store, guild_id, key)
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(default)
}

fn setting_u64_optional(store: &Store, guild_id: &str, key: &str) -> Option<u64> {
    setting_string(store, guild_id, key).and_then(|value| value.parse::<u64>().ok())
}

fn setting_i64(store: &Store, guild_id: &str, key: &str, default: i64) -> i64 {
    setting_string(store, guild_id, key)
        .and_then(|value| value.parse::<i64>().ok())
        .unwrap_or(default)
}

fn setting_bool(store: &Store, guild_id: &str, key: &str, default: bool) -> bool {
    setting_string(store, guild_id, key)
        .and_then(|value| value.parse::<bool>().ok())
        .unwrap_or(default)
}

fn levels_config_for_store(store: &Store, guild_id: &str) -> serde_json::Value {
    let ignored_channels = setting_string(store, guild_id, "community.levels.ignored_channels")
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .take(100)
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let level_roles = setting_string(store, guild_id, "community.levels.level_roles")
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .take(50)
        .map(str::to_owned)
        .collect::<Vec<_>>();
    serde_json::json!({
        "xpMin": setting_i64(store, guild_id, "community.levels.xp_min", 15),
        "xpMax": setting_i64(store, guild_id, "community.levels.xp_max", 30),
        "cooldownSeconds": setting_u64(store, guild_id, "community.levels.cooldown_seconds", 60),
        "voiceXpEnabled": setting_bool(store, guild_id, "community.levels.voice_xp_enabled", false),
        "voiceXpPerMinute": setting_i64(store, guild_id, "community.levels.voice_xp_per_minute", 2),
        "ignoredChannels": ignored_channels,
        "levelRoles": level_roles,
        "stackRoles": setting_bool(store, guild_id, "community.levels.stack_roles", true),
        "announceChannel": setting_string(store, guild_id, "community.levels.announce_channel").unwrap_or_default(),
        "announceTemplate": setting_string(store, guild_id, "community.levels.announce_template").unwrap_or_else(|| "{member} reached level {level}!".into()),
    })
}

fn economy_config_for_store(store: &Store, guild_id: &str) -> serde_json::Value {
    serde_json::json!({
        "currencyName": setting_string(store, guild_id, "community.economy.currency_name")
            .unwrap_or_else(|| "credits".into()),
        "dailyReward": setting_i64(store, guild_id, "community.economy.daily_reward", 100),
        "workReward": setting_i64(store, guild_id, "community.economy.work_reward", 50),
        "workCooldownMinutes": setting_u64(
            store,
            guild_id,
            "community.economy.work_cooldown_ms",
            3_600_000,
        )
        .saturating_div(60_000),
    })
}

fn moderation_policy_for_store(store: &Store, guild_id: &str) -> ModerationPolicy {
    ModerationPolicy {
        require_reason: setting_bool(
            store,
            guild_id,
            "management.moderation.require_reason",
            true,
        ),
        max_purge: setting_u64(store, guild_id, "management.moderation.max_purge", 100)
            .clamp(1, 100),
    }
}

fn moderation_decision(
    store: &Store,
    guild_id: &str,
    action: &str,
    reason: &str,
    requested_count: Option<i64>,
) -> helper_core::ModerationDecision {
    evaluate_moderation(
        &moderation_policy_for_store(store, guild_id),
        &ModerationObservation {
            action: action.to_owned(),
            reason: reason.to_owned(),
            requested_count,
        },
    )
}

fn reminder_policy_for_store(store: &Store, guild_id: &str) -> ReminderPolicy {
    ReminderPolicy {
        max_delay_hours: setting_u64(store, guild_id, "utility.reminders.max_delay_hours", 168)
            .clamp(1, 8_760),
        max_text_length: setting_u64(store, guild_id, "utility.reminders.max_text_length", 500)
            .clamp(50, 500) as usize,
        timezone: setting_string(store, guild_id, "utility.reminders.timezone")
            .unwrap_or_else(|| "UTC".into()),
        notify_user: setting_bool(store, guild_id, "utility.reminders.notify_user", true),
        allow_recurring: setting_bool(store, guild_id, "utility.reminders.allow_recurring", false),
        max_recurrences: setting_u64(store, guild_id, "utility.reminders.max_recurrences", 12)
            .clamp(1, 52),
    }
}

fn anti_spam_policy_for_store(store: &Store, guild_id: &str) -> AntiSpamPolicy {
    let csv = |key: &str| {
        setting_string(store, guild_id, key)
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .collect::<Vec<_>>()
    };
    anti_spam_policy_from_json(&serde_json::json!({
        "floodCount": setting_u64(store, guild_id, "security.antispam.flood_count", 6),
        "windowSeconds": setting_u64(store, guild_id, "security.antispam.window_seconds", 10),
        "duplicateLimit": setting_u64(store, guild_id, "security.antispam.duplicate_limit", 3),
        "mentionLimit": setting_u64(store, guild_id, "security.antispam.mention_limit", 5),
        "maxLinks": setting_u64(store, guild_id, "security.antispam.max_links", 5),
        "capsPercent": setting_u64(store, guild_id, "security.antispam.caps_percent", 80),
        "capsMinLetters": setting_u64(store, guild_id, "security.antispam.caps_min_letters", 8),
        "timeoutSeconds": setting_u64(store, guild_id, "security.antispam.timeout_seconds", 60),
        "ignoredChannels": csv("security.antispam.ignored_channels"),
        "ignoredRoles": csv("security.antispam.ignored_roles"),
        "alertOnly": setting_bool(store, guild_id, "security.antispam.alert_only", false),
        "deleteMessage": setting_bool(store, guild_id, "security.antispam.delete_message", false),
    }))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AntiSpamWarningTargets {
    chat: bool,
    dm: bool,
}

/// Resolve where the automatic anti-spam warning is delivered. Existing
/// servers do not have this setting projected yet, so absence and malformed
/// legacy values deliberately use the safest visible default: both targets.
fn anti_spam_warning_targets(delivery: Option<&str>) -> AntiSpamWarningTargets {
    match delivery.map(str::trim) {
        Some("chat") => AntiSpamWarningTargets {
            chat: true,
            dm: false,
        },
        Some("dm") => AntiSpamWarningTargets {
            chat: false,
            dm: true,
        },
        Some("both") | None => AntiSpamWarningTargets {
            chat: true,
            dm: true,
        },
        Some(_) => AntiSpamWarningTargets {
            chat: true,
            dm: true,
        },
    }
}

/// Turn internal anti-spam signal identifiers into an explanation that a
/// member or moderator can understand without knowing implementation details.
fn anti_spam_warning_reason(matched: &[String]) -> String {
    let mut reasons = matched
        .iter()
        .filter_map(|signal| match signal.as_str() {
            "flood" => Some("sending too many messages in a short time"),
            "duplicate" => Some("repeating the same message"),
            "mentions" => Some("mentioning too many people"),
            "links" => Some("posting too many links"),
            "caps" => Some("using too many capital letters"),
            _ => None,
        })
        .collect::<Vec<_>>();

    match reasons.len() {
        0 => "unusual message activity".to_owned(),
        1 => reasons[0].to_owned(),
        2 => format!("{} and {}", reasons[0], reasons[1]),
        _ => {
            let last = reasons.pop().expect("multiple anti-spam reasons");
            format!("{}, and {last}", reasons.join(", "))
        }
    }
}

fn anti_spam_log_message(user_id: &str, matched: &[String], should_act: bool) -> String {
    let reason = anti_spam_warning_reason(matched);
    let detection = if reason == "unusual message activity" {
        format!("Unusual message activity was detected from <@{user_id}>.")
    } else {
        format!("<@{user_id}> was {reason}.")
    };
    let outcome = if should_act {
        "Vozen Helper took the action selected in this server's settings."
    } else {
        "No action was taken; this was logged for review."
    };

    format!("⚠️ Anti-spam alert: {detection} {outcome}")
}

fn anti_spam_member_explanation(matched: &[String]) -> String {
    let reason = anti_spam_warning_reason(matched);
    if reason == "unusual message activity" {
        "Anti-spam detected unusual message activity.".to_owned()
    } else {
        format!("Anti-spam detected that you were {reason}.")
    }
}

/// Measure content once before entering the shared anti-spam evaluator. URL
/// tokens count toward the link rule but do not distort the uppercase ratio.
fn anti_spam_content_metrics(content: &str) -> (u32, u32, u32) {
    let mut links = 0_u32;
    let mut uppercase_letters = 0_u32;
    let mut letters = 0_u32;

    for raw_token in content.split_whitespace() {
        let token = raw_token.trim_matches(|character: char| {
            character.is_ascii_punctuation() && character != '/' && character != ':'
        });
        let normalized = token.to_ascii_lowercase();
        if normalized.starts_with("http://")
            || normalized.starts_with("https://")
            || normalized.starts_with("www.")
        {
            links = links.saturating_add(1);
            continue;
        }
        for character in token.chars() {
            if character.is_alphabetic() {
                letters = letters.saturating_add(1);
                if character.is_uppercase() {
                    uppercase_letters = uppercase_letters.saturating_add(1);
                }
            }
        }
    }

    (links, uppercase_letters, letters)
}

fn scam_policy_for_store(store: &Store, guild_id: &str) -> helper_core::ScamPolicy {
    let list = |key: &str| {
        setting_string(store, guild_id, key)
            .unwrap_or_default()
            .lines()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .collect::<Vec<_>>()
    };
    scam_policy_from_json(&serde_json::json!({
        "blockInvites": setting_bool(store, guild_id, "security.antiscam.block_invites", true),
        "blockedDomains": list("security.antiscam.blocked_domains"),
        "blockedKeywords": list("security.antiscam.blocked_keywords"),
        "ignoredChannels": list("security.antiscam.ignored_channels"),
        "ignoredRoles": list("security.antiscam.ignored_roles"),
        "logChannel": setting_string(store, guild_id, "security.antiscam.log_channel").unwrap_or_default(),
        "timeoutSeconds": setting_u64(store, guild_id, "security.antiscam.timeout_seconds", 300),
        "deleteMessage": setting_bool(store, guild_id, "security.antiscam.delete_message", true),
        "alertOnly": setting_bool(store, guild_id, "security.antiscam.alert_only", false),
    }))
}

fn starboard_policy_for_store(store: &Store, guild_id: &str) -> helper_core::StarboardPolicy {
    let csv = |key: &str| {
        setting_string(store, guild_id, key)
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .collect::<Vec<_>>()
    };
    starboard_policy_from_json(&serde_json::json!({
        "threshold": setting_i64(store, guild_id, "community.starboard.threshold", 3),
        "allowSelfStar": setting_bool(store, guild_id, "community.starboard.allow_self_star", false),
        "includeImages": setting_bool(store, guild_id, "community.starboard.include_images", true),
        "ignoredChannels": csv("community.starboard.ignored_channels"),
        "ignoredRoles": csv("community.starboard.ignored_roles"),
    }))
}

fn starboard_message_content(
    policy: &helper_core::StarboardPolicy,
    emoji: &str,
    count: i64,
    original: &serenity::all::Message,
    link: &str,
) -> starboard_display::Content {
    let attachments = if policy.include_images {
        original
            .attachments
            .iter()
            .take(4)
            .map(|attachment| attachment.url.as_str())
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    let author_id = original.author.id.to_string();
    let compact = render_starboard_content(emoji, count, &author_id, "", &attachments, link);
    let (caption, footer) = compact.split_once("\n\n").unwrap_or((&compact, link));
    starboard_display::Content {
        caption: caption.into(),
        footer: footer.into(),
        fallback: render_starboard_content(
            emoji,
            count,
            &author_id,
            &original.content,
            &attachments,
            link,
        ),
    }
}

fn render_starboard_content(
    emoji: &str,
    count: i64,
    author_id: &str,
    original_content: &str,
    attachments: &[&str],
    link: &str,
) -> String {
    const MESSAGE_LIMIT: usize = 2_000;
    let noun = if count == 1 { "star" } else { "stars" };
    let prefix = format!("{emoji} **Message spotlight** · **{count} {noun}**\nBy <@{author_id}>");
    let source_link = format!("\n\n{link}");
    let mut attachment_text = String::new();
    let mut reserved = prefix.encode_utf16().count() + source_link.encode_utf16().count();
    for attachment in attachments.iter().take(4) {
        let length = 1 + attachment.encode_utf16().count();
        if reserved + length <= MESSAGE_LIMIT {
            attachment_text.push('\n');
            attachment_text.push_str(attachment);
            reserved += length;
        }
    }
    let available = MESSAGE_LIMIT.saturating_sub(reserved);
    // Quote every line so the original text remains distinct from bot metadata.
    let quoted = if original_content.trim().is_empty() {
        String::new()
    } else {
        format!("\n\n> {}", original_content.replace('\n', "\n> "))
    };
    let original_length = quoted.encode_utf16().count();
    let budget = if original_length > available {
        available.saturating_sub(1)
    } else {
        available
    };
    let mut excerpt = String::new();
    let mut used = 0;
    for character in quoted.chars() {
        let length = character.len_utf16();
        if used + length > budget {
            break;
        }
        excerpt.push(character);
        used += length;
    }
    if original_length > available && available > 0 {
        excerpt.push('…');
    }
    format!("{prefix}{excerpt}{source_link}{attachment_text}")
}

fn starboard_reaction_count(
    normal_reactions: u64,
    author_in_first_page: bool,
    allow_self_star: bool,
) -> u64 {
    if allow_self_star {
        normal_reactions
    } else if author_in_first_page || normal_reactions > 100 {
        // Above 100, the first page cannot prove that the author did not react.
        normal_reactions.saturating_sub(1)
    } else {
        normal_reactions
    }
}

fn suggestion_author_label(id: i64, author_id: &str, published_content: &str) -> String {
    if published_content.starts_with(&format!("**Suggestion #{id}** by <@{author_id}>\n")) {
        format!("<@{author_id}>")
    } else {
        // A changed setting must not reveal an author who was published anonymously.
        "Anonymous".to_string()
    }
}

fn render_suggestion_message(
    id: i64,
    author: &str,
    text: &str,
    status: &str,
    up: i64,
    down: i64,
) -> String {
    format!(
        "**Suggestion #{id}** by {author}\n{text}\n\nStatus: **{status}** · Support: {up} · Against: {down}"
    )
}

fn suggestion_message_fits(content: &str) -> bool {
    // Leave room for longer status labels and growing vote counts on later edits.
    content.encode_utf16().count() <= 1_900
}

/// Starboard mirrors user-authored content, so never allow arbitrary mentions
/// from that content to ping a whole server. The original author mention is
/// retained explicitly because it is part of the board's attribution.
fn starboard_allowed_mentions(author_id: serenity::all::UserId) -> CreateAllowedMentions {
    CreateAllowedMentions::new()
        .users([author_id])
        .replied_user(false)
}

fn giveaway_allowed_mentions(winners: &[String]) -> CreateAllowedMentions {
    let users = winners
        .iter()
        .filter_map(|winner| winner.parse::<u64>().ok())
        .map(serenity::all::UserId::new)
        .collect::<Vec<_>>();
    CreateAllowedMentions::new()
        .everyone(false)
        .empty_roles()
        .users(users)
        .replied_user(false)
}

fn permission_passport_message() -> String {
    "**Permission Passport**\nBase: `View Channels`, `Send Messages`, `Embed Links`, `Read Message History`, `Use Application Commands`.\nOptional security: `Manage Messages`, `Moderate Members`, `Kick Members`, `Ban Members`, `Manage Roles`.\nOptional support/events: `Manage Channels`, `Manage Threads`, `Create Private Threads`.\nGateway: `MESSAGE_CONTENT` and `GUILD_MEMBERS` must be enabled for the app at gateway startup; their data is processed only by configured modules that need it.\nEvery extra permission has a module and an explicit consequence; use the dashboard to compare granted permissions with the required ones.".to_string()
}

fn parse_scheduled_event_window(
    start_raw: &str,
    end_raw: &str,
    now_timestamp: i64,
) -> Result<(serenity::all::Timestamp, serenity::all::Timestamp), &'static str> {
    let start = serenity::all::Timestamp::parse(start_raw).map_err(|_| "invalid_start")?;
    let end = serenity::all::Timestamp::parse(end_raw).map_err(|_| "invalid_end")?;
    if start.unix_timestamp() <= now_timestamp {
        return Err("start_must_be_in_future");
    }
    if end.unix_timestamp() <= start.unix_timestamp() {
        return Err("end_must_follow_start");
    }
    if end.unix_timestamp() - start.unix_timestamp() > 365 * 86_400 {
        return Err("event_too_long");
    }
    Ok((start, end))
}

async fn deliver_birthday_announcements(
    http: &serenity::http::Http,
    store: &Store,
    now: DateTime<Utc>,
) -> Result<()> {
    for setting in store.enabled_feature_settings("community.birthdays")? {
        let mut config: serde_json::Value =
            serde_json::from_str(&setting.config_json).unwrap_or_default();
        // Read legacy projections during the rolling migration, then pass a
        // single effective config to the same evaluator used by previews.
        if !config.is_object() {
            config = serde_json::json!({});
        }
        if let Some(object) = config.as_object_mut() {
            for (field, projection_key) in [
                ("channel", "community.birthdays.channel_id"),
                ("message", "community.birthdays.message"),
                ("timezone", "community.birthdays.timezone"),
            ] {
                if !object.contains_key(field)
                    && let Some(value) = setting_string(store, &setting.guild_id, projection_key)
                {
                    object.insert(field.into(), serde_json::Value::String(value));
                }
            }
        }
        let timezone = config
            .get("timezone")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("UTC")
            .to_string();
        let Some(offset_minutes) = parse_utc_offset_minutes(&timezone) else {
            warn!(guild_id = %setting.guild_id, timezone, "skipping birthdays with invalid timezone");
            continue;
        };
        let Some(offset) = FixedOffset::east_opt(offset_minutes.saturating_mul(60)) else {
            continue;
        };
        let local = now.with_timezone(&offset);
        let (year, month, day) = (local.year(), local.month(), local.day());
        let birthdays = store.due_birthdays_for_guild(&setting.guild_id, month, day, year, 500)?;
        for birthday in birthdays {
            let decision = evaluate_birthday(&config, &birthday.user_id, month, day);
            if !decision.allowed {
                warn!(
                    guild_id = %setting.guild_id,
                    user_id = %birthday.user_id,
                    reason = decision.reason_code,
                    "skipping birthday with invalid delivery configuration"
                );
                continue;
            }
            let Ok(channel_id) = decision.channel_id.parse::<u64>() else {
                continue;
            };
            let Ok(user_id) = birthday.user_id.parse::<u64>() else {
                warn!(guild_id = %setting.guild_id, user_id = %birthday.user_id, "skipping birthday with invalid member id");
                continue;
            };
            let message = CreateMessage::new()
                .content(decision.message)
                .allowed_mentions(
                    CreateAllowedMentions::new().users([serenity::all::UserId::new(user_id)]),
                );
            if ChannelId::new(channel_id)
                .send_message(http, message)
                .await
                .is_ok()
            {
                let _ = store.mark_birthday_announced(&birthday.guild_id, &birthday.user_id, year);
            }
        }
    }
    Ok(())
}

fn schedule_event_reminder(
    store: &Store,
    guild_id: &str,
    event_id: &str,
    event_name: &str,
    start: serenity::all::Timestamp,
) -> Result<()> {
    store.delete_scheduled_actions_for(guild_id, "event_reminder", event_id)?;
    if !setting_bool(store, guild_id, "community.events.reminders", true) {
        return Ok(());
    }
    let Some(channel_id) =
        setting_string(store, guild_id, "community.events.announcement_channel_id")
            .and_then(|value| value.parse::<u64>().ok())
    else {
        // A reminder without a real destination is not useful. The scheduled
        // action was removed above, so correcting the channel later is safe.
        return Ok(());
    };
    let reminder_hours =
        setting_u64(store, guild_id, "community.events.reminder_hours", 1).clamp(1, 168) as i64;
    let now_ms = Utc::now().timestamp_millis();
    let start_ms = start.unix_timestamp().saturating_mul(1_000);
    let execute_at = start_ms
        .saturating_sub(reminder_hours.saturating_mul(3_600_000))
        .max(now_ms);
    let payload = serde_json::json!({
        "channel_id": channel_id.to_string(),
        "event_id": event_id,
        "text": format!("Reminder: **{}** starts <t:{}:R>.", event_name, start.unix_timestamp()),
    });
    store.schedule_typed(
        guild_id,
        "event_reminder",
        event_id,
        execute_at,
        &payload.to_string(),
    )?;
    Ok(())
}

async fn deliver_scheduled_action(
    http: &serenity::http::Http,
    store: &Store,
    id: i64,
    guild_id: &str,
    action_type: &str,
    target_id: &str,
    payload: &str,
) -> Result<()> {
    let value: serde_json::Value = serde_json::from_str(payload).unwrap_or_default();
    if action_type == "anti_spam_untimeout" {
        let guild = guild_id
            .parse::<u64>()
            .map(serenity::all::GuildId::new)
            .map_err(|_| anyhow::anyhow!("invalid anti-spam timeout guild"))?;
        let user = target_id
            .parse::<u64>()
            .map(serenity::all::UserId::new)
            .map_err(|_| anyhow::anyhow!("invalid anti-spam timeout user"))?;
        let expected_until_unix = value
            .get("expected_until_unix")
            .and_then(serde_json::Value::as_i64)
            .ok_or_else(|| anyhow::anyhow!("anti-spam timeout deadline missing"))?;
        let member = guild.member(http, user).await?;
        let current_until_unix = member
            .communication_disabled_until
            .as_ref()
            .map(|timestamp| timestamp.unix_timestamp());
        if should_clear_anti_spam_timeout(
            expected_until_unix,
            current_until_unix,
            Utc::now().timestamp(),
        ) {
            guild
                .edit_member(
                    http,
                    user,
                    serenity::all::EditMember::new().enable_communication(),
                )
                .await?;
            info!(%guild_id, %target_id, "released expired anti-spam timeout");
        }
        store.delete_scheduled_action(id)?;
        return Ok(());
    }
    // Scheduled work can outlive the revision that created it.  Consume jobs
    // for a feature that was disabled instead of allowing stale actions to
    // mutate the server after the owner turned that module off.
    let gated_feature = scheduled_action_feature(action_type);
    if gated_feature.is_some_and(|key| !feature_enabled(store, guild_id, key, None)) {
        store.delete_scheduled_action(id)?;
        return Ok(());
    }
    if action_type == "reminder" && !feature_enabled(store, guild_id, "utility.reminders", None) {
        // A scheduled reminder may outlive a feature disable. Consume it without
        // delivering anything so a later re-enable cannot replay stale notices.
        store.delete_scheduled_action(id)?;
        return Ok(());
    }
    if action_type == "unban" {
        let guild = guild_id
            .parse::<u64>()
            .map(serenity::all::GuildId::new)
            .map_err(|_| anyhow::anyhow!("invalid scheduled unban guild"))?;
        let user = target_id
            .parse::<u64>()
            .map(serenity::all::UserId::new)
            .map_err(|_| anyhow::anyhow!("invalid scheduled unban user"))?;
        if let Err(error) = guild.unban(http, user).await {
            // Unknown Ban is already released; transient failures retain the job.
            if !discord_error_code(&error, 10026) {
                return Err(error.into());
            }
        }
        store.delete_scheduled_action(id)?;
        return Ok(());
    }
    if action_type == "giveaway_end" {
        if let Some(giveaway_id) = value.get("giveaway_id").and_then(serde_json::Value::as_i64) {
            let _ = finish_giveaway(http, store, guild_id, giveaway_id).await?;
        }
        store.delete_scheduled_action(id)?;
        return Ok(());
    }
    if action_type == "poll_end" {
        if let Some(poll_id) = value.get("poll_id").and_then(serde_json::Value::as_i64) {
            let _ = finish_poll(http, store, guild_id, poll_id).await?;
        }
        store.delete_scheduled_action(id)?;
        return Ok(());
    }
    if action_type == "ticket_sla" {
        if let Some(raw_channel) = value.get("channel_id").and_then(serde_json::Value::as_str)
            && let Ok(Some(ticket)) = store.ticket_by_channel(raw_channel)
            && ticket.status == "open"
            && ticket.guild_id == guild_id
            && ticket.claimed_by.is_none()
            && let Ok(channel) = raw_channel.parse::<u64>()
        {
            let _ = ChannelId::new(channel)
                .say(
                    http,
                    "⏱️ This ticket is waiting for a reply from the support team.",
                )
                .await;
        }
        store.delete_scheduled_action(id)?;
        return Ok(());
    }
    if action_type == "monetization_entitlement" {
        if !feature_enabled(store, guild_id, "growth.monetization", None) {
            store.delete_scheduled_action(id)?;
            return Ok(());
        }
        let member_id = value
            .get("member_id")
            .and_then(serde_json::Value::as_str)
            .and_then(|raw| raw.parse::<u64>().ok())
            .map(serenity::all::UserId::new)
            .ok_or_else(|| anyhow::anyhow!("invalid monetization member"))?;
        let role_id = value
            .get("role_id")
            .and_then(serde_json::Value::as_str)
            .and_then(|raw| raw.parse::<u64>().ok())
            .map(RoleId::new)
            .ok_or_else(|| anyhow::anyhow!("invalid monetization role"))?;
        let guild = guild_id
            .parse::<u64>()
            .map(serenity::all::GuildId::new)
            .map_err(|_| anyhow::anyhow!("invalid monetization guild"))?;
        let roles = guild.roles(http).await?;
        let Some(role) = roles.get(&role_id) else {
            store.delete_scheduled_action(id)?;
            return Ok(());
        };
        if role.managed {
            store.delete_scheduled_action(id)?;
            return Ok(());
        }
        let bot_user = http.get_current_user().await?;
        let bot_member = guild.member(http, bot_user.id).await?;
        let bot_top = bot_member
            .roles
            .iter()
            .filter_map(|rid| roles.get(rid).map(|r| r.position))
            .max()
            .unwrap_or(0);
        if role.position >= bot_top {
            store.delete_scheduled_action(id)?;
            return Ok(());
        }
        guild
            .member(http, member_id)
            .await?
            .add_role(http, role_id)
            .await?;
        store.delete_scheduled_action(id)?;
        return Ok(());
    }
    if action_type == "web3_wallet_role_sync" {
        if !feature_enabled(store, guild_id, "web3.gating", None) {
            store.delete_scheduled_action(id)?;
            return Ok(());
        }
        let member_id = value
            .get("member_id")
            .and_then(serde_json::Value::as_str)
            .and_then(|raw| raw.parse::<u64>().ok())
            .map(serenity::all::UserId::new)
            .ok_or_else(|| anyhow::anyhow!("invalid wallet member"))?;
        let role_id = value
            .get("role_id")
            .and_then(serde_json::Value::as_str)
            .and_then(|raw| raw.parse::<u64>().ok())
            .map(RoleId::new)
            .ok_or_else(|| anyhow::anyhow!("invalid wallet role"))?;
        let chain = value
            .get("chain")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("wallet chain missing"))?;
        let contract = value
            .get("contract_address")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("wallet contract missing"))?;
        if !approved_wallet_contract(contract) {
            store.delete_scheduled_action(id)?;
            return Ok(());
        }
        let address = value
            .get("address")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("wallet address missing"))?;
        let asset_type = value
            .get("asset_type")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("erc721");
        let token_id = value.get("token_id").and_then(serde_json::Value::as_str);
        let minimum = value
            .get("minimum_balance")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("wallet minimum balance missing"))?
            .parse::<u128>()
            .map_err(|_| anyhow::anyhow!("wallet minimum balance invalid"))?;
        let interval_seconds = value
            .get("interval_seconds")
            .and_then(serde_json::Value::as_i64)
            .unwrap_or(3600)
            .clamp(900, 86_400);
        let rpc = EthereumRpcClient::from_env(chain)
            .ok_or_else(|| anyhow::anyhow!("wallet rpc not configured"))?;
        let balance = rpc
            .token_balance(contract, address, asset_type, token_id)
            .await?;
        let guild = guild_id
            .parse::<u64>()
            .map(serenity::all::GuildId::new)
            .map_err(|_| anyhow::anyhow!("invalid wallet guild"))?;
        let roles = guild.roles(http).await?;
        let Some(role) = roles.get(&role_id) else {
            store.delete_scheduled_action(id)?;
            return Ok(());
        };
        if role.managed {
            store.delete_scheduled_action(id)?;
            return Ok(());
        }
        let bot_user = http.get_current_user().await?;
        let bot_member = guild.member(http, bot_user.id).await?;
        let bot_top = bot_member
            .roles
            .iter()
            .filter_map(|rid| roles.get(rid).map(|item| item.position))
            .max()
            .unwrap_or(0);
        if role.position >= bot_top {
            store.delete_scheduled_action(id)?;
            return Ok(());
        }
        let member = guild.member(http, member_id).await?;
        if balance >= minimum {
            member.add_role(http, role_id).await?;
        } else {
            member.remove_role(http, role_id).await?;
        }
        let next_payload = serde_json::json!({
            "address": address,
            "member_id": member_id.get().to_string(),
            "role_id": role_id.get().to_string(),
            "chain": chain,
            "contract_address": contract,
            "asset_type": asset_type,
            "token_id": token_id,
            "minimum_balance": minimum.to_string(),
            "interval_seconds": interval_seconds,
        });
        let _ = store.schedule_typed(
            guild_id,
            "web3_wallet_role_sync",
            &member_id.get().to_string(),
            Utc::now().timestamp_millis() + interval_seconds * 1_000,
            &next_payload.to_string(),
        );
        store.delete_scheduled_action(id)?;
        return Ok(());
    }
    let channel_id = value
        .get("channel_id")
        .and_then(serde_json::Value::as_str)
        .and_then(|raw| raw.parse::<u64>().ok())
        .map(ChannelId::new);
    if let Some(channel_id) = channel_id {
        let text = value
            .get("text")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("You have a pending reminder.");
        let notify_user = setting_bool(store, guild_id, "utility.reminders.notify_user", true);
        let content = if action_type == "reminder" && notify_user {
            format!("<@{target_id}> ⏰ {text}")
        } else {
            text.to_string()
        };
        let mut message = serenity::all::CreateMessage::new()
            .content(content)
            .allowed_mentions(CreateAllowedMentions::new().users(
                if action_type == "reminder" && notify_user {
                    target_id
                        .parse::<u64>()
                        .ok()
                        .filter(|id| *id > 0)
                        .map(serenity::all::UserId::new)
                } else {
                    None
                },
            ));
        if action_type == "event_reminder" {
            // Event names are user-controlled; never let a reminder turn an
            // event title into an unexpected @everyone or role mention.
            message = message.allowed_mentions(serenity::all::CreateAllowedMentions::new());
        }
        channel_id.send_message(http, message).await?;
        if action_type == "reminder"
            && let Some(repeat) = value.get("repeat").and_then(serde_json::Value::as_str)
            && let Some(remaining) = value.get("remaining").and_then(serde_json::Value::as_u64)
            && remaining > 0
            && let Some(interval_ms) = reminder_repeat_interval_ms(repeat)
        {
            let mut next_payload = value.clone();
            next_payload["remaining"] = serde_json::json!(remaining - 1);
            let _ = store.schedule_typed(
                guild_id,
                "reminder",
                target_id,
                Utc::now().timestamp_millis() + interval_ms,
                &next_payload.to_string(),
            )?;
        }
    }
    store.delete_scheduled_action(id)?;
    Ok(())
}

fn reminder_repeat_interval_ms(repeat: &str) -> Option<i64> {
    match repeat {
        "daily" => Some(86_400_000),
        "weekly" => Some(604_800_000),
        _ => None,
    }
}

fn approved_wallet_contract(value: &str) -> bool {
    let body = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"));
    body.is_some_and(|text| text.len() == 40 && text.bytes().all(|byte| byte.is_ascii_hexdigit()))
        && std::env::var("SIWE_ALLOWED_CONTRACTS")
            .ok()
            .is_some_and(|list| {
                list.split(',')
                    .any(|item| item.trim().eq_ignore_ascii_case(value))
            })
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn failed_quarantine_restore_keeps_pending_roles_for_retry() {
        let store = helper_store::Store::open(":memory:").unwrap();
        let roles = vec!["10".into(), "20".into()];
        store.begin_quarantine("g", "u", &roles, "reason").unwrap();
        let result = super::restore_quarantine_roles(&store, "g", "u", &roles, "reason", |role| {
            std::future::ready(role.get() == 10)
        })
        .await
        .unwrap();
        assert_eq!(result, (1, 1));
        let saved = store.get_quarantine("g", "u").unwrap().unwrap();
        assert_eq!(saved.role_ids, vec!["20"]);
        let result = super::restore_quarantine_roles(
            &store,
            "g",
            "u",
            &saved.role_ids,
            &saved.reason,
            |_| std::future::ready(true),
        )
        .await
        .unwrap();
        assert_eq!(result, (1, 0));
        assert!(store.get_quarantine("g", "u").unwrap().is_none());
    }

    #[tokio::test]
    async fn invalid_quarantine_roles_remain_saved_without_discord_calls() {
        let store = helper_store::Store::open(":memory:").unwrap();
        let roles = vec!["0".into(), "invalid".into()];
        store.begin_quarantine("g", "u", &roles, "reason").unwrap();
        let mut calls = 0;
        let result = super::restore_quarantine_roles(&store, "g", "u", &roles, "reason", |_| {
            calls += 1;
            std::future::ready(true)
        })
        .await
        .unwrap();
        assert_eq!(result, (0, 2));
        assert_eq!(calls, 0);
        assert_eq!(
            store.get_quarantine("g", "u").unwrap().unwrap().role_ids,
            roles
        );
    }

    #[tokio::test]
    async fn unpublished_poll_results_keep_the_job_even_after_votes_close() {
        let store = helper_store::Store::open(":memory:").unwrap();
        store
            .set_setting("g", "feature.management.polls", "true")
            .unwrap();
        let poll = store
            .create_scheduled_poll("g", "10", "Question", &["Yes".into(), "No".into()], 0)
            .unwrap();
        let job = store.due_scheduled_actions(0, 1).unwrap().pop().unwrap();
        let http = serenity::http::Http::new("test-only");
        for _ in 0..2 {
            assert!(
                super::deliver_scheduled_action(
                    &http, &store, job.0, "g", "poll_end", &job.3, &job.4
                )
                .await
                .is_err()
            );
            assert!(store.poll(poll).unwrap().unwrap().closed);
            assert_eq!(store.due_scheduled_actions(0, 1).unwrap().len(), 1);
        }
    }

    #[test]
    fn poll_panels_and_results_do_not_expand_user_supplied_mentions() {
        let options = ["@everyone".into(), "<@&123>".into()];
        let store = helper_store::Store::open(":memory:").unwrap();
        let id = store.create_poll("g", "10", "<@456>", &options, 0).unwrap();
        let poll = store.poll(id).unwrap().unwrap();
        let panel = serde_json::to_value(super::poll_open_message(id, &poll.question, &options, 0))
            .unwrap();
        let result = serde_json::to_value(super::poll_result_message(&poll, &[1, 2])).unwrap();
        for message in [panel, result] {
            assert_eq!(message["allowed_mentions"]["parse"], serde_json::json!([]));
        }
    }

    #[test]
    fn giveaway_mentions_only_the_selected_winners() {
        let panel = serde_json::to_value(super::giveaway_allowed_mentions(&[])).unwrap();
        assert_eq!(panel["parse"], serde_json::json!([]));
        assert_eq!(panel["users"], serde_json::json!([]));
        assert_eq!(panel["roles"], serde_json::json!([]));

        let result = serde_json::to_value(super::giveaway_allowed_mentions(&[
            "123".into(),
            "not-a-user".into(),
        ]))
        .unwrap();
        assert_eq!(result["parse"], serde_json::json!([]));
        assert_eq!(result["users"], serde_json::json!(["123"]));
        assert_eq!(result["roles"], serde_json::json!([]));
    }

    #[test]
    fn suggestion_author_visibility_follows_the_published_message() {
        assert_eq!(
            super::suggestion_author_label(42, "99", "**Suggestion #42** by Anonymous\nText"),
            "Anonymous"
        );
        assert_eq!(
            super::suggestion_author_label(42, "99", "**Suggestion #42** by <@99>\nText"),
            "<@99>"
        );
        assert_eq!(super::suggestion_author_label(42, "99", ""), "Anonymous");
    }

    #[test]
    fn suggestion_message_rejects_emoji_text_over_discord_limit() {
        let short =
            super::render_suggestion_message(1, "Anonymous", &"🌟".repeat(500), "pending", 0, 0);
        let long =
            super::render_suggestion_message(1, "Anonymous", &"🌟".repeat(1_000), "pending", 0, 0);
        assert!(super::suggestion_message_fits(&short));
        assert!(!super::suggestion_message_fits(&long));
    }

    #[test]
    fn starboard_spotlight_has_natural_singular_plural_and_quoted_original() {
        let link = "https://discord.com/channels/1/2/3";
        for (count, noun) in [(1, "star"), (2, "stars"), (0, "stars")] {
            let mirror =
                super::render_starboard_content("⭐", count, "42", "Hello\nWorld", &[], link);
            assert!(mirror.starts_with(&format!(
                "⭐ **Message spotlight** · **{count} {noun}**\nBy <@42>"
            )));
            assert!(mirror.contains("\n\n> Hello\n> World"));
            assert!(mirror.ends_with(link));
        }
    }

    #[test]
    fn starboard_compact_caption_keeps_attribution_source_and_attachment() {
        let link = "https://discord.com/channels/1/2/3";
        let caption = super::render_starboard_content(
            "⭐",
            1,
            "42",
            "",
            &["https://cdn.discord.test/image.png"],
            link,
        );
        assert!(caption.contains("By <@42>"));
        assert!(caption.contains(link));
        assert!(caption.contains("https://cdn.discord.test/image.png"));
        assert!(!caption.contains("> "));
        assert!(caption.encode_utf16().count() <= 2_000);
    }

    #[test]
    fn starboard_multiline_quotes_remain_within_discord_limit() {
        let mirror = super::render_starboard_content(
            "⭐",
            100,
            "42",
            &"🌟\n".repeat(1_500),
            &[],
            "https://discord.com/channels/1/2/3",
        );
        assert!(mirror.encode_utf16().count() <= 2_000);
        assert!(mirror.contains('…'));
        assert!(mirror.contains("https://discord.com/channels/1/2/3"));
    }

    #[test]
    fn starboard_mirror_keeps_source_link_with_long_unicode_text() {
        let link = "https://discord.com/channels/1/2/3";
        let mirror = super::render_starboard_content(
            "⭐",
            4,
            "42",
            &"🌟".repeat(1_500),
            &["https://cdn.discord.test/image.png"],
            link,
        );
        assert!(mirror.encode_utf16().count() <= 2_000);
        assert!(mirror.contains(link));
        assert!(mirror.contains("https://cdn.discord.test/image.png"));
        assert!(mirror.contains('…'));
    }

    #[test]
    fn starboard_mirror_omits_attachments_that_do_not_fit() {
        let oversized_url = format!("https://cdn.discord.test/{}", "x".repeat(2_000));
        let mirror = super::render_starboard_content(
            "⭐",
            3,
            "42",
            "Hello",
            &[oversized_url.as_str()],
            "https://discord.com/channels/1/2/3",
        );
        assert!(mirror.encode_utf16().count() <= 2_000);
        assert!(mirror.contains("Hello"));
        assert!(!mirror.contains(&oversized_url));
    }

    #[test]
    fn starboard_reaction_count_reaches_the_maximum_threshold_with_101_votes() {
        assert_eq!(super::starboard_reaction_count(101, true, false), 100);
        assert_eq!(super::starboard_reaction_count(101, false, false), 100);
        assert_eq!(super::starboard_reaction_count(101, false, true), 101);
    }

    #[test]
    fn tiktok_runtime_accepts_creator_oauth_without_a_global_token() {
        assert!(super::tiktok_runtime_allowed(true, false, true, false));
        assert!(super::tiktok_runtime_allowed(false, true, true, false));
    }

    #[test]
    fn tiktok_runtime_keeps_approval_and_credentials_required() {
        assert!(!super::tiktok_runtime_allowed(false, false, true, true));
        assert!(!super::tiktok_runtime_allowed(false, true, false, true));
        assert!(!super::tiktok_runtime_allowed(true, false, false, false));
        assert!(super::tiktok_runtime_allowed(true, false, false, true));
    }

    #[tokio::test]
    async fn tiktok_creator_client_is_guild_scoped_and_sandbox_has_no_global_fallback() {
        let store = helper_store::Store::open(":memory:").unwrap();
        let cipher = super::TokenCipher::new("test-secret-at-least-thirty-two-bytes").unwrap();
        let oauth = super::TikTokOAuthClient::new(
            "test-client",
            "test-client-secret",
            "https://example.test/callback",
            "https://www.tiktok.com/v2/auth/authorize/",
            "https://open.tiktokapis.com/v2/oauth/token/",
        )
        .unwrap();
        let fallback =
            super::TikTokClient::new("test-global-token", "https://open.tiktokapis.com").unwrap();
        let now = chrono::Utc::now().timestamp();
        store
            .save_tiktok_grant(
                "guild-a",
                "test-creator",
                "Creator",
                &cipher.seal("test-creator-access").unwrap(),
                &cipher.seal("test-creator-refresh").unwrap(),
                "user.info.basic,video.list",
                now + 3600,
                now + 7200,
                now,
            )
            .unwrap();
        let creator = super::tiktok_client_for_guild(
            &store,
            "guild-a",
            Some(&oauth),
            Some(&cipher),
            None,
            false,
        )
        .await
        .unwrap();
        assert!(creator.is_configured());
        assert!(
            super::tiktok_client_for_guild(
                &store,
                "guild-b",
                Some(&oauth),
                Some(&cipher),
                Some(&fallback),
                false,
            )
            .await
            .is_err()
        );
        assert!(
            super::tiktok_client_for_guild(&store, "guild-b", None, None, Some(&fallback), true,)
                .await
                .is_ok()
        );
        store.delete_tiktok_grant("guild-a").unwrap();
        assert!(
            super::tiktok_client_for_guild(
                &store,
                "guild-a",
                Some(&oauth),
                Some(&cipher),
                Some(&fallback),
                false,
            )
            .await
            .is_err()
        );
    }

    use super::{
        HELPER_LANGUAGE_SETTING, HELPER_LOCALES, account_age_days,
        adapter::{DiscordAdapter, Effect, FakeDiscordAdapter},
        anti_nuke_containment_deadline, anti_spam_content_metrics, anti_spam_log_message,
        anti_spam_warning_reason, anti_spam_warning_targets, command_feature_key,
        custom_command_channel_ignored, custom_command_is_staff, english_bot_text,
        evaluate_join_gate_verification, evaluate_nickname, feature_enabled, feature_title,
        helper_command_counts_as_value, helper_gateway_intents, helper_locale,
        helper_locale_for_guild, helper_setup_is_complete, instagram_access_allowed,
        is_destructive_audit_action, join_burst_armed, parse_custom_command, parse_duration,
        parse_reminder_delay, parse_scheduled_event_window, permission_passport_message,
        reminder_repeat_interval_ms, render_custom_command, rss_retry_seconds,
        scheduled_action_feature, shadow_mode_enabled, should_cleanup_temp_channel,
        should_clear_anti_spam_timeout, ticket_member_is_staff, ticket_opening_message,
        unified_welcome_text,
    };
    use chrono::TimeZone;
    use helper_store::Store;
    use serenity::all::GatewayIntents;
    use std::{
        collections::{HashMap, VecDeque},
        time::{Duration, Instant},
    };

    #[test]
    fn welcome_buttons_link_to_the_configured_guild_channels() {
        let config = serde_json::json!({"rulesChannel":"456","introductionsChannel":"789","channelsChannel":"321"});
        for (step, label, emoji, channel) in [
            ("rules", "Read the rules", "📜", "456"),
            ("introductions", "Introduce yourself", "👋", "789"),
            ("channels", "Explore channels", "🧭", "321"),
        ] {
            let button =
                serde_json::to_value(super::welcome_guide_button("123", step, &config).unwrap())
                    .unwrap();
            assert_eq!(
                button["url"],
                format!("https://discord.com/channels/123/{channel}")
            );
            assert!(button.get("custom_id").is_none());
            assert_eq!(button["label"], label);
            assert_eq!(button["style"], 5);
            assert_eq!(button["emoji"]["name"], emoji);
        }
        let other_guild =
            serde_json::to_value(super::welcome_guide_button("999", "rules", &config).unwrap())
                .unwrap();
        assert_eq!(other_guild["url"], "https://discord.com/channels/999/456");
    }

    #[test]
    fn welcome_buttons_omit_unset_or_invalid_destinations() {
        for (step, field) in [
            ("rules", "rulesChannel"),
            ("introductions", "introductionsChannel"),
            ("channels", "channelsChannel"),
        ] {
            assert!(super::welcome_guide_button("123", step, &serde_json::json!({})).is_none());
            for value in [
                serde_json::json!(null),
                serde_json::json!(true),
                serde_json::json!(456),
                serde_json::json!(""),
                serde_json::json!("0"),
                serde_json::json!("-1"),
                serde_json::json!("invalid"),
                serde_json::json!("12/34"),
                serde_json::json!("https://example.com"),
                serde_json::json!("18446744073709551616"),
            ] {
                let mut config = serde_json::json!({});
                config[field] = value;
                assert!(super::welcome_guide_button("123", step, &config).is_none());
            }
        }
        let partial = serde_json::json!({"rulesChannel":"456"});
        let buttons: Vec<_> = ["rules", "introductions", "channels"]
            .into_iter()
            .filter_map(|step| super::welcome_guide_button("123", step, &partial))
            .collect();
        assert_eq!(buttons.len(), 1);
        for guild in ["", "0", "invalid", "12/34"] {
            assert!(super::welcome_guide_button(guild, "rules", &partial).is_none());
        }
        assert!(super::welcome_guide_button("123", "unknown", &partial).is_none());
        let help =
            serde_json::to_value(super::welcome_guide_button("123", "help", &partial).unwrap())
                .unwrap();
        assert_eq!(help["custom_id"], "welcome:step:123:help");
        assert_eq!(help["style"], 2);
    }

    #[test]
    fn gateway_intents_are_bounded_and_the_passport_explains_app_level_access() {
        let intents = helper_gateway_intents();

        assert!(intents.contains(GatewayIntents::GUILDS));
        assert!(intents.contains(GatewayIntents::GUILD_MEMBERS));
        assert!(intents.contains(GatewayIntents::MESSAGE_CONTENT));
        assert!(!intents.contains(GatewayIntents::GUILD_PRESENCES));
        assert!(!intents.contains(GatewayIntents::DIRECT_MESSAGES));
        assert!(!intents.contains(GatewayIntents::DIRECT_MESSAGE_REACTIONS));

        let passport = permission_passport_message();
        assert!(passport.contains("enabled for the app at gateway startup"));
        assert!(passport.contains("processed only by configured modules"));
        assert!(!passport.contains("enabled only for modules"));
    }

    #[test]
    fn growth_first_value_excludes_onboarding_and_diagnostics() {
        for command in [
            "ping",
            "language",
            "help",
            "setup",
            "modules",
            "status",
            "dashboard",
            "plan",
            "privacy",
            "permissions",
        ] {
            assert!(
                !helper_command_counts_as_value(command),
                "{command} must not count as first value"
            );
        }

        for command in [
            "warn",
            "ticket-panel",
            "rolepanel",
            "event-create",
            "workflow-dry-run",
            "serverstats",
        ] {
            assert!(
                helper_command_counts_as_value(command),
                "{command} should count as first value after success"
            );
        }
    }

    #[test]
    fn growth_setup_requires_at_least_one_saved_module() {
        let store = Store::open(":memory:").expect("open test store");

        assert!(!helper_setup_is_complete(&store, "guild"));
        store
            .set_setting("guild", "core.setup.completed", "false")
            .unwrap();
        assert!(!helper_setup_is_complete(&store, "guild"));
        store
            .set_setting("guild", "core.setup.completed", "true")
            .unwrap();
        assert!(helper_setup_is_complete(&store, "guild"));
    }

    #[test]
    fn helper_language_defaults_to_english_and_only_accepts_site_locales() {
        let store = Store::open(":memory:").expect("open test store");

        assert_eq!(helper_locale_for_guild(&store, "guild").unwrap(), "en");
        assert_eq!(HELPER_LOCALES.len(), 10);
        assert_eq!(helper_locale("en"), Some(("en", "English")));
        assert_eq!(helper_locale("pt"), Some(("pt", "Português")));
        assert_eq!(helper_locale("pt-BR"), None);
        assert_eq!(helper_locale("ja"), None);

        store
            .set_setting("guild", HELPER_LANGUAGE_SETTING, "ru")
            .unwrap();
        assert_eq!(helper_locale_for_guild(&store, "guild").unwrap(), "ru");

        // Old/unapproved values are never used as a fallback language.
        store
            .set_setting("guild", HELPER_LANGUAGE_SETTING, "pt-BR")
            .unwrap();
        assert_eq!(helper_locale_for_guild(&store, "guild").unwrap(), "en");
    }

    #[test]
    fn instagram_development_mode_only_bypasses_the_external_approval_gate() {
        assert!(instagram_access_allowed(true, false));
        assert!(instagram_access_allowed(false, true));
        assert!(instagram_access_allowed(true, true));
        assert!(!instagram_access_allowed(false, false));
    }

    #[test]
    fn anti_spam_release_only_clears_the_timeout_it_created() {
        assert!(should_clear_anti_spam_timeout(1_000, Some(1_000), 1_000));
        assert!(should_clear_anti_spam_timeout(1_000, Some(1_002), 1_001));
        assert!(!should_clear_anti_spam_timeout(1_000, Some(1_120), 1_001));
        assert!(!should_clear_anti_spam_timeout(1_000, Some(1_000), 999));
        assert!(!should_clear_anti_spam_timeout(1_000, None, 1_001));
    }

    #[test]
    fn anti_spam_content_metrics_counts_links_without_skewing_caps_detection() {
        assert_eq!(
            anti_spam_content_metrics("LOUD https://vozen.org/docs, www.vozen.org"),
            (2, 4, 4)
        );
    }

    #[test]
    fn anti_spam_warning_delivery_supports_chat_dm_and_both() {
        let default_targets = anti_spam_warning_targets(None);
        assert!(default_targets.chat);
        assert!(default_targets.dm);

        let chat_targets = anti_spam_warning_targets(Some("chat"));
        assert!(chat_targets.chat);
        assert!(!chat_targets.dm);

        let dm_targets = anti_spam_warning_targets(Some("dm"));
        assert!(!dm_targets.chat);
        assert!(dm_targets.dm);

        let both_targets = anti_spam_warning_targets(Some("both"));
        assert!(both_targets.chat);
        assert!(both_targets.dm);

        let invalid_targets = anti_spam_warning_targets(Some("invalid"));
        assert!(invalid_targets.chat);
        assert!(invalid_targets.dm);
    }

    #[test]
    fn anti_spam_alerts_explain_the_detection_in_plain_language() {
        let matched = vec!["flood".to_owned()];

        assert_eq!(
            anti_spam_warning_reason(&matched),
            "sending too many messages in a short time"
        );
        assert_eq!(
            anti_spam_log_message("42", &matched, true),
            "⚠️ Anti-spam alert: <@42> was sending too many messages in a short time. Vozen Helper took the action selected in this server's settings."
        );
    }

    #[test]
    fn anti_spam_alerts_join_multiple_reasons_naturally() {
        let matched = vec![
            "duplicate".to_owned(),
            "mentions".to_owned(),
            "links".to_owned(),
        ];

        assert_eq!(
            anti_spam_warning_reason(&matched),
            "repeating the same message, mentioning too many people, and posting too many links"
        );
        assert_eq!(
            anti_spam_log_message("42", &["future-rule".to_owned()], false),
            "⚠️ Anti-spam alert: Unusual message activity was detected from <@42>. No action was taken; this was logged for review."
        );
    }

    #[test]
    fn verification_panel_promotes_members_and_clears_the_quarantine_role() {
        let decision = evaluate_join_gate_verification(
            &[serenity::all::RoleId::new(7)],
            Some(serenity::all::RoleId::new(7)),
            serenity::all::RoleId::new(9),
        );

        assert!(decision.assign_verified_role);
        assert!(decision.remove_quarantine_role);
        assert!(!decision.already_verified);
    }

    #[test]
    fn verification_panel_never_removes_the_verified_role_when_roles_are_misconfigured() {
        let role = serenity::all::RoleId::new(7);
        let decision = evaluate_join_gate_verification(&[role], Some(role), role);

        assert!(!decision.assign_verified_role);
        assert!(!decision.remove_quarantine_role);
        assert!(decision.already_verified);
    }

    #[test]
    fn translates_legacy_user_facing_messages_to_english() {
        assert_eq!(
            english_bot_text("Ol\u{00e1} <@1>. Explica aqui o que precisas."),
            "Hello <@1>. Tell us what you need."
        );
        assert_eq!(
            english_bot_text(
                "N\u{00e3}o foi poss\u{00ed}vel executar a a\u{00e7}\u{00e3}o; confirma as permiss\u{00f5}es e a hierarquia de cargos."
            ),
            "Unable to perform the action; check permissions and role hierarchy."
        );
        assert_eq!(
            english_bot_text("Olá <@1>. Explica aqui o que precisas."),
            "Hello <@1>. Tell us what you need."
        );
        assert_eq!(
            english_bot_text("Ticket fechado e arquivado. O canal não foi apagado."),
            "Ticket closed and archived. The channel was not deleted."
        );
        assert_eq!(
            english_bot_text("Este comando só pode ser usado num servidor."),
            "This command can only be used in a server."
        );
        for (source, expected) in [
            ("Indica um canal válido.", "Specify a valid channel."),
            (
                "As sugestões estão desativadas neste servidor. Ativa-as no painel.",
                "Suggestions are disabled in this server. Enable them in the dashboard.",
            ),
            ("Evento nativo #12 criado:", "Native event #12 created:"),
            (
                "Ticket atualizado: categoria **support**.",
                "Ticket updated: category **support**.",
            ),
            ("AFK definido: away", "AFK status set: away"),
            ("Cargo atribuído.", "Role assigned."),
            (
                "Não tens o cargo necessário para participar.",
                "You do not have the required role to participate.",
            ),
            (
                "Este ticket já está aberto ou não existe.",
                "This ticket is already open or does not exist.",
            ),
            (
                "Esta poll já terminou ou a opção é inválida.",
                "This poll has ended or the option is invalid.",
            ),
        ] {
            assert_eq!(english_bot_text(source), expected);
        }
        assert_eq!(
            english_bot_text(
                "Setup guiado: escolhe pelo menos um m\u{00f3}dulo (Security, Support, Events, Community, Automate ou Insights) e executa novamente. Depois confirma as permiss\u{00f5}es com `/permissions`."
            ),
            "Guided setup: choose at least one module (Security, Support, Events, Community, Automate or Insights), then run it again. Confirm permissions with `/permissions`."
        );
        assert_eq!(
            english_bot_text(
                "Setup guardado para: **Security**. Pr\u{00f3}ximo passo: `/permissions` e depois configura cada m\u{00f3}dulo."
            ),
            "Setup saved for: **Security**. Next step: `/permissions` and then configure each module."
        );
        assert_eq!(
            english_bot_text(
                "Setup: **conclu\u{00ed}do** · M\u{00f3}dulos: **Security** · Isolamento por guild ativo · Privacy export/delete dispon\u{00ed}vel"
            ),
            "Setup: **complete** · Modules: **Security** · Guild isolation enabled · Privacy export/delete available"
        );
    }

    #[test]
    fn custom_commands_parse_bounded_names_and_arguments() {
        assert_eq!(
            parse_custom_command("!rules please read this", "!"),
            Some(super::ParsedCustomCommand {
                name: "rules".into(),
                args: "please read this".into(),
            })
        );
        assert!(parse_custom_command("rules", "!").is_none());
        assert!(parse_custom_command("!bad.name", "!").is_none());
        assert!(parse_custom_command("!rules", "?").is_none());
    }

    #[test]
    fn rss_delivery_backoff_is_bounded_and_grows_after_failures() {
        assert_eq!(rss_retry_seconds(300, 0), 300);
        assert_eq!(rss_retry_seconds(900, 1), 1_800);
        assert_eq!(rss_retry_seconds(900, 4), 3_600);
        assert_eq!(rss_retry_seconds(86_400, 8), 3_600);
        assert_eq!(rss_retry_seconds(1, -2), 300);
    }

    #[test]
    fn custom_commands_render_variables_and_neutralize_broadcast_mentions() {
        let rendered = render_custom_command(
            "Hello {user} in {channel} on {server}: {args} @everyone @here",
            serenity::all::UserId::new(7),
            serenity::all::ChannelId::new(8),
            "Test server",
            "welcome",
            2000,
        );
        assert!(rendered.contains("<@7>"));
        assert!(rendered.contains("<#8>"));
        assert!(rendered.contains("Test server"));
        assert!(rendered.contains("welcome"));
        assert!(!rendered.contains("@everyone"));
        assert!(!rendered.contains("@here"));
        assert!(rendered.chars().count() <= 2000);
    }

    #[test]
    fn custom_commands_respect_channel_and_staff_guards() {
        assert!(custom_command_channel_ignored(
            Some("7,8".into()),
            serenity::all::ChannelId::new(8)
        ));
        assert!(!custom_command_channel_ignored(
            Some("7".into()),
            serenity::all::ChannelId::new(8)
        ));
        assert!(!custom_command_is_staff(None));
        assert!(custom_command_is_staff(Some(
            serenity::all::Permissions::MANAGE_GUILD
        )));
    }

    #[test]
    fn ticket_opening_message_notifies_only_the_configured_support_role() {
        let message = ticket_opening_message(
            serenity::all::UserId::new(7),
            Some(serenity::all::RoleId::new(9)),
        );
        assert!(message.contains("<@7>"));
        assert!(message.contains("<@&9>"));
        assert!(message.contains("I've called"));
        assert!(!message.contains("@everyone"));

        let message_without_staff = ticket_opening_message(serenity::all::UserId::new(7), None);
        assert!(message_without_staff.contains("<@7>"));
        assert!(!message_without_staff.contains("<@&"));
        assert!(!message_without_staff.contains("I've called"));
        let mentions = serde_json::to_value(super::ticket_opening_mentions(
            serenity::all::UserId::new(7),
            Some(serenity::all::RoleId::new(9)),
        ))
        .unwrap();
        assert_eq!(mentions["users"], serde_json::json!(["7"]));
        assert_eq!(mentions["roles"], serde_json::json!(["9"]));
        assert_eq!(mentions["parse"], serde_json::json!([]));
        let no_staff = serde_json::to_value(super::ticket_opening_mentions(
            serenity::all::UserId::new(7),
            None,
        ))
        .unwrap();
        assert_eq!(no_staff["roles"], serde_json::json!([]));
    }

    #[test]
    fn ticket_actions_accept_support_role_and_server_administrators() {
        let staff_role = serenity::all::RoleId::new(9);
        assert!(ticket_member_is_staff(
            Some(staff_role),
            &[staff_role],
            serenity::all::Permissions::empty(),
            false,
        ));
        assert!(ticket_member_is_staff(
            Some(staff_role),
            &[],
            serenity::all::Permissions::MANAGE_CHANNELS,
            false,
        ));
        assert!(ticket_member_is_staff(
            None,
            &[],
            serenity::all::Permissions::ADMINISTRATOR,
            false,
        ));
        assert!(ticket_member_is_staff(
            None,
            &[],
            serenity::all::Permissions::empty(),
            true,
        ));
        assert!(!ticket_member_is_staff(
            Some(staff_role),
            &[],
            serenity::all::Permissions::empty(),
            false,
        ));
    }

    #[test]
    fn every_catalogue_key_has_a_gateway_reference() {
        let source = include_str!("lib.rs");
        for key in helper_core::FEATURE_KEYS {
            assert!(
                source.contains(&format!("\"{key}\"")),
                "catalogue feature {key} has no Discord runtime reference"
            );
        }
    }

    #[test]
    fn every_published_projection_has_a_discord_runtime_consumer() {
        // Adapters are allowed to publish several bounded settings, but a
        // setting exposed by the panel must be read by this Discord runtime
        // (handler, command or provider worker). This is intentionally a
        // source-level guard: it catches a new field being persisted without
        // silently becoming a no-op in production.
        let source = include_str!("lib.rs");
        let api_source = include_str!("../../helper-api/src/lib.rs");
        let store_source = include_str!("../../helper-store/src/lib.rs");
        for key in helper_core::FEATURE_KEYS {
            let adapter = helper_core::feature_adapter(key).expect("catalogue adapter");
            // Provider subscriptions are deliberately projected twice: the
            // API transaction stores a durable provider record and the
            // Discord worker consumes that record. Their source-specific
            // projection names are not generic `set_setting` keys, so guard
            // the complete provider path instead of demanding a dead string
            // lookup in the gateway crate.
            let dedicated_provider_consumer = match *key {
                "support.welcome" | "support.welcome_channel" => {
                    source.contains(".welcome_configuration(")
                        && include_str!("../../helper-store/src/welcome.rs")
                            .contains("fn welcome_variant(")
                }
                "social.youtube" => {
                    api_source.contains("publish_youtube_feature_setting")
                        && store_source.contains("due_youtube_subscriptions")
                        && source.contains("process_youtube_subscription")
                }
                "social.rss" | "social.podcasts" => {
                    api_source.contains("publish_rss_feature_setting")
                        && store_source.contains("due_rss_subscriptions")
                        && source.contains("process_rss_subscription")
                }
                "social.twitch" => {
                    api_source.contains("publish_twitch_feature_setting")
                        && store_source.contains("due_twitch_subscriptions")
                        && source.contains("process_twitch_subscription")
                }
                "social.tiktok" => {
                    api_source.contains("publish_tiktok_feature_setting")
                        && store_source.contains("due_tiktok_subscriptions")
                        && source.contains("process_tiktok_subscription")
                }
                "social.instagram" => {
                    api_source.contains("publish_instagram_feature_setting")
                        && store_source.contains("due_instagram_subscriptions")
                        && source.contains("process_instagram_subscription")
                }
                "social.kick" => {
                    api_source.contains("publish_kick_feature_setting")
                        && store_source.contains("due_kick_subscriptions")
                        && source.contains("process_kick_subscription")
                }
                "social.bluesky" => {
                    api_source.contains("publish_bluesky_feature_setting")
                        && store_source.contains("due_bluesky_subscriptions")
                        && source.contains("process_bluesky_subscription")
                }
                // Monetization is consumed by the signed Stripe webhook in
                // the API and by the idempotent entitlement job in this
                // gateway, rather than by a polling worker.
                "growth.monetization" => {
                    api_source.contains("stripe_webhook")
                        && source.contains("monetization_entitlement")
                }
                // Wallet gating is a signed API flow that schedules this
                // gateway's idempotent role reconciliation job.
                "web3.gating" => {
                    api_source.contains("web3_gating_verify")
                        && source.contains("web3_wallet_role_sync")
                }
                // These read-only providers are scheduled workers. Their
                // projection namespace is built from the feature key so the
                // runtime can share one worker across collection/network
                // variants; the worker itself is the consumer contract.
                "web3.gas_tracker" => {
                    source.contains("run_gas_tracker_worker")
                        && source.contains("web3.gas_tracker.interval_seconds")
                }
                "web3.crypto_stats" => {
                    source.contains("run_crypto_stats_worker")
                        && source.contains("enabled_feature_settings(\"web3.crypto_stats\")")
                }
                _ => false,
            };
            for (setting, _) in adapter.runtime_projection(&adapter.descriptor().defaults) {
                assert!(
                    dedicated_provider_consumer || source.contains(&setting),
                    "{key} publishes {setting}, but helper-discord has no runtime consumer"
                );
            }
        }
    }

    #[test]
    fn duration_parser_is_bounded_and_explicit() {
        assert_eq!(parse_duration("10m"), Some(600_000));
        assert_eq!(parse_duration("2h"), Some(7_200_000));
        assert_eq!(parse_duration(" 365d "), Some(31_536_000_000));
        for invalid in [
            "",
            "é",
            "10秒",
            "10💥",
            "-1m",
            "366d",
            "9223372036854775807d",
        ] {
            assert_eq!(parse_duration(invalid), None, "duration: {invalid}");
        }
        assert_eq!(parse_duration("0m"), None);
        assert_eq!(parse_duration("10weeks"), None);
        assert_eq!(account_age_days(172800, 86400), 1);
        assert_eq!(account_age_days(86400, 172800), 0);
    }

    #[test]
    fn join_burst_arms_once_and_resets_after_threshold() {
        let mut joins: HashMap<String, VecDeque<Instant>> = HashMap::new();
        let start = Instant::now();
        let window = Duration::from_secs(10);
        assert!(!join_burst_armed(&mut joins, "guild", start, window, 3));
        assert!(!join_burst_armed(
            &mut joins,
            "guild",
            start + Duration::from_secs(1),
            window,
            3
        ));
        assert!(join_burst_armed(
            &mut joins,
            "guild",
            start + Duration::from_secs(2),
            window,
            3
        ));
        assert!(!join_burst_armed(
            &mut joins,
            "guild",
            start + Duration::from_secs(3),
            window,
            3
        ));
    }

    #[test]
    fn join_burst_ignores_expired_entries() {
        let mut joins: HashMap<String, VecDeque<Instant>> = HashMap::new();
        let start = Instant::now();
        let window = Duration::from_secs(3);
        assert!(!join_burst_armed(&mut joins, "guild", start, window, 2));
        assert!(!join_burst_armed(
            &mut joins,
            "guild",
            start + Duration::from_secs(4),
            window,
            2
        ));
    }

    #[test]
    fn anti_nuke_action_filter_is_destructive_only() {
        assert!(is_destructive_audit_action(
            serenity::model::guild::audit_log::Action::Role(
                serenity::model::guild::audit_log::RoleAction::Delete,
            )
        ));
        assert!(is_destructive_audit_action(
            serenity::model::guild::audit_log::Action::Member(
                serenity::model::guild::audit_log::MemberAction::BanAdd,
            )
        ));
        assert!(!is_destructive_audit_action(
            serenity::model::guild::audit_log::Action::Role(
                serenity::model::guild::audit_log::RoleAction::Create,
            )
        ));
        assert!(!is_destructive_audit_action(
            serenity::model::guild::audit_log::Action::GuildUpdate
        ));
    }

    #[test]
    fn anti_nuke_containment_deadline_is_temporary_and_bounded() {
        assert_eq!(anti_nuke_containment_deadline(1_000, 10), 1_600);
        assert_eq!(anti_nuke_containment_deadline(1_000, 0), 1_060);
        assert_eq!(anti_nuke_containment_deadline(1_000, 999), 8_200);
    }

    #[test]
    fn scheduled_event_window_requires_rfc3339_future_and_bounded_end() {
        let now = serenity::all::Timestamp::parse("2026-07-24T00:00:00Z").unwrap();
        assert!(
            parse_scheduled_event_window(
                "2026-07-24T01:00:00Z",
                "2026-07-24T02:00:00Z",
                now.unix_timestamp()
            )
            .is_ok()
        );
        assert_eq!(
            parse_scheduled_event_window(
                "2026-07-23T23:00:00Z",
                "2026-07-24T02:00:00Z",
                now.unix_timestamp()
            )
            .unwrap_err(),
            "start_must_be_in_future"
        );
        assert_eq!(
            parse_scheduled_event_window(
                "2026-07-24T01:00:00Z",
                "2026-07-24T01:00:00Z",
                now.unix_timestamp()
            )
            .unwrap_err(),
            "end_must_follow_start"
        );
        assert_eq!(
            parse_scheduled_event_window(
                "2026-07-24T01:00:00Z",
                "2027-07-25T01:00:00Z",
                now.unix_timestamp()
            )
            .unwrap_err(),
            "event_too_long"
        );
    }

    #[test]
    fn shadow_mode_is_explicit_and_case_insensitive() {
        assert!(shadow_mode_enabled(Some("true")));
        assert!(shadow_mode_enabled(Some("TRUE")));
        assert!(!shadow_mode_enabled(Some("false")));
        assert!(!shadow_mode_enabled(None));
    }

    #[test]
    fn fake_discord_records_antispam_effects_and_surfaces_failures() {
        let mut discord = FakeDiscordAdapter::new();
        discord
            .timeout_member("guild", "member", 60, "matched:flood")
            .unwrap();
        discord
            .log("log-channel", "Anti-spam: matched:flood (action)")
            .unwrap();
        discord.reply("general", "Please slow down.").unwrap();
        discord
            .create_channel("guild", "ticket", "ticket-123", "text")
            .unwrap();
        discord.assign_role("guild", "member", "verified").unwrap();
        discord
            .publish_event("guild", "event", "Community meetup")
            .unwrap();
        discord
            .edit_channel("ticket", "ticket-123-claimed")
            .unwrap();
        discord.remove_role("guild", "member", "verified").unwrap();
        discord.delete_channel("ticket").unwrap();
        let nickname = evaluate_nickname(&serde_json::json!({"nickname": "Vozen Helper"}));
        assert!(nickname.allowed);
        discord
            .change_nickname("guild", "helper", Some(&nickname.nickname))
            .unwrap();
        assert_eq!(discord.effects().len(), 10);
        assert!(matches!(
            discord.effects()[0],
            Effect::Timeout { seconds: 60, .. }
        ));
        assert!(matches!(
            discord.effects()[9],
            Effect::ChangeNickname {
                ref guild_id,
                ref member_id,
                ref nickname,
            } if guild_id == "guild" && member_id == "helper" && nickname.as_deref() == Some("Vozen Helper")
        ));

        discord.fail_next();
        let error = discord.log("log-channel", "permission check").unwrap_err();
        assert_eq!(error, "discord_permission_denied");
        assert_eq!(discord.effects().len(), 10);
    }

    #[test]
    fn canonical_feature_switches_control_help_privacy_and_tickets() {
        let store = Store::open(":memory:").expect("open test store");
        assert!(!feature_enabled(&store, "guild", "utility.help", None));
        store
            .set_setting("guild", "feature.utility.help", "true")
            .unwrap();
        assert!(feature_enabled(&store, "guild", "utility.help", None));

        store
            .publish_feature_setting(
                "guild",
                "utility.help",
                false,
                "{}",
                None,
                "owner",
                &[("feature.utility.help".into(), "true".into())],
            )
            .unwrap();
        assert!(!feature_enabled(&store, "guild", "utility.help", None));

        store
            .set_setting("guild", "feature.management.privacy", "true")
            .unwrap();
        assert!(feature_enabled(&store, "guild", "management.privacy", None));
        store
            .set_setting("guild", "feature.management.privacy", "false")
            .unwrap();
        assert!(!feature_enabled(
            &store,
            "guild",
            "management.privacy",
            None
        ));

        // A provider setup page is intentionally configurable in the panel,
        // but a stale/manual flag must not bypass its credential and approval
        // gate in the Discord runtime.
        store
            .set_setting("guild", "feature.social.instagram", "true")
            .unwrap();
        assert!(!feature_enabled(&store, "guild", "social.instagram", None));

        // Ticket components accept the legacy key while all new writes use
        // the canonical key; both paths must have the same runtime meaning.
        store
            .set_setting("guild", "feature.support.tickets", "true")
            .unwrap();
        assert!(feature_enabled(
            &store,
            "guild",
            "support.tickets",
            Some("feature.support.tickets")
        ));
        store
            .set_setting("guild", "feature.support.tickets", "false")
            .unwrap();
        assert!(!feature_enabled(
            &store,
            "guild",
            "support.tickets",
            Some("feature.support.tickets")
        ));
    }

    #[test]
    fn command_feature_map_covers_mutating_and_provider_commands() {
        let expected = [
            ("join-gate", "protection.join_gate"),
            ("anti-raid", "protection.anti_raid"),
            ("anti-nuke", "management.audit"),
            ("lockdown", "management.moderation"),
            ("unlock", "management.moderation"),
            ("tag-set", "management.custom_commands"),
            ("rank", "studio.rank_card"),
            ("leaderboard", "community.leaderboard"),
            ("crypto", "web3.crypto_queries"),
            ("giveaway-start", "community.giveaways"),
            ("poll", "management.polls"),
            ("workflow-create", "management.workflows"),
            ("event-create", "community.events"),
            ("birthday-set", "community.birthdays"),
            ("rolepanel", "community.role_panels"),
            ("ticket-panel", "support.tickets"),
            ("remind", "utility.reminders"),
            ("search", "utility.search"),
            ("embed", "utility.embeds"),
        ];
        for (command, feature) in expected {
            assert_eq!(command_feature_key(command), Some(feature), "{command}");
            assert_ne!(feature_title(feature), "this feature");
        }
        assert_eq!(command_feature_key("ping"), None);
        assert_eq!(command_feature_key("dashboard"), None);
    }

    #[test]
    fn scheduled_actions_are_consumed_when_their_feature_is_disabled() {
        assert_eq!(
            scheduled_action_feature("giveaway_end"),
            Some("community.giveaways")
        );
        assert_eq!(
            scheduled_action_feature("poll_end"),
            Some("management.polls")
        );
        assert_eq!(
            scheduled_action_feature("ticket_sla"),
            Some("support.tickets")
        );
        // Releasing a temporary sanction must survive a moderation toggle
        // being disabled after the sanction was created.
        assert_eq!(scheduled_action_feature("unban"), None);
        assert_eq!(scheduled_action_feature("reminder"), None);
    }

    #[test]
    fn recurring_reminders_only_accept_bounded_intervals() {
        assert_eq!(reminder_repeat_interval_ms("daily"), Some(86_400_000));
        assert_eq!(reminder_repeat_interval_ms("weekly"), Some(604_800_000));
        assert_eq!(reminder_repeat_interval_ms("hourly"), None);
    }

    #[test]
    fn reminder_clock_times_use_the_configured_utc_offset() {
        let now = chrono::Utc
            .with_ymd_and_hms(2026, 8, 5, 12, 0, 0)
            .single()
            .expect("valid fixture")
            .timestamp_millis();
        let utc_delay = parse_reminder_delay("09:30", "UTC", now).expect("UTC time");
        let plus_two_delay = parse_reminder_delay("09:30", "UTC+02:00", now).expect("offset time");
        assert_eq!(utc_delay, 21 * 60 * 60 * 1_000 + 30 * 60 * 1_000);
        assert_eq!(plus_two_delay, 19 * 60 * 60 * 1_000 + 30 * 60 * 1_000);
        assert!(parse_reminder_delay("25:00", "UTC", now).is_none());
        assert!(parse_reminder_delay("09:30", "Europe/Lisbon", now).is_none());
    }

    #[test]
    fn temporary_channel_cleanup_waits_for_a_full_disconnect() {
        assert!(should_cleanup_temp_channel(None));
        assert!(!should_cleanup_temp_channel(Some(
            serenity::all::ChannelId::new(42)
        )));
    }

    #[test]
    fn studio_templates_render_only_bounded_message_content() {
        let path = std::env::temp_dir().join(format!(
            "vozen-helper-template-test-{}.sqlite",
            std::process::id()
        ));
        let store = Store::open(&path).expect("open test store");
        store
            .set_setting("guild", "feature.management.templates", "true")
            .unwrap();
        store
            .set_setting("guild", "support.welcome.template_id", "welcome-1")
            .unwrap();
        store
            .set_setting(
                "guild",
                "studio.template.welcome-1",
                &serde_json::json!({"config":{"content":"Hello {member}, @everyone"}}).to_string(),
            )
            .unwrap();
        assert_eq!(
            unified_welcome_text(
                &store,
                "guild",
                &serde_json::json!({"templateId":"welcome-1"}),
                "welcome",
                "fallback"
            ),
            "Hello {member}, @\u{200b}everyone"
        );
        // A stale projection must not keep the template active after the
        // feature publisher explicitly disables the module.
        store
            .set_setting("guild", "management.templates.enabled", "false")
            .unwrap();
        assert_eq!(
            unified_welcome_text(
                &store,
                "guild",
                &serde_json::json!({"templateId":"welcome-1"}),
                "welcome",
                "fallback"
            ),
            "fallback"
        );
        store
            .set_setting("guild", "management.templates.enabled", "true")
            .unwrap();
        store
            .set_setting(
                "guild",
                "studio.template.welcome-1",
                &serde_json::json!({"config":{"content":"\u{0000}"}}).to_string(),
            )
            .unwrap();
        assert_eq!(
            unified_welcome_text(
                &store,
                "guild",
                &serde_json::json!({"templateId":"welcome-1"}),
                "welcome",
                "fallback"
            ),
            "fallback"
        );
        store
            .set_setting("guild", "feature.management.templates", "false")
            .unwrap();
        assert_eq!(
            unified_welcome_text(
                &store,
                "guild",
                &serde_json::json!({"templateId":"welcome-1"}),
                "welcome",
                "fallback"
            ),
            "fallback"
        );
        let _ = std::fs::remove_file(path);
    }
}
