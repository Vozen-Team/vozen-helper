use super::*;
use serenity::all::{GuildId, UserId, VoiceState};

#[derive(Default)]
pub(super) struct TempChannels {
    // Gateway snapshots include all voice occupants, including after a fresh connection.
    occupants: Mutex<HashMap<GuildId, HashMap<UserId, ChannelId>>>,
    operations: tokio::sync::Mutex<()>,
}

impl TempChannels {
    fn channel(&self, guild: GuildId, user: UserId) -> Option<ChannelId> {
        self.occupants
            .lock()
            .unwrap()
            .get(&guild)?
            .get(&user)
            .copied()
    }

    fn empty(&self, guild: GuildId, channel: ChannelId) -> bool {
        self.occupants
            .lock()
            .unwrap()
            .get(&guild)
            .is_some_and(|members| !members.values().any(|id| *id == channel))
    }

    pub(super) fn forget(&self, guild: GuildId) {
        self.occupants.lock().unwrap().remove(&guild);
    }

    pub(super) async fn seed(&self, ctx: &Context, store: &Store, guild: &Guild) {
        self.occupants.lock().unwrap().insert(
            guild.id,
            guild
                .voice_states
                .iter()
                .filter_map(|(user, state)| state.channel_id.map(|channel| (*user, channel)))
                .collect(),
        );
        let _guard = self.operations.lock().await;
        // Reconcile only our durable room records; the creator is never a room record.
        if let Ok(rooms) = store.temp_channels(&guild.id.to_string()) {
            for room in rooms {
                if let Ok(id) = room.channel_id.parse::<u64>() {
                    self.cleanup(ctx, store, guild.id, ChannelId::new(id)).await;
                }
            }
        }
    }

    async fn cleanup(&self, ctx: &Context, store: &Store, guild: GuildId, channel: ChannelId) {
        if !self.empty(guild, channel) {
            return;
        }
        let Ok(Some(record)) = store.temp_channel(&channel.to_string()) else {
            return;
        };
        if record.guild_id != guild.to_string() || creator(store, guild) == Some(channel) {
            return;
        }
        match channel.delete(&ctx.http).await {
            Ok(_) => {
                let _ = store.remove_temp_channel(&channel.to_string());
            }
            Err(error) => {
                if missing_channel(&error) {
                    let _ = store.remove_temp_channel(&channel.to_string());
                } else {
                    warn!(%guild, %channel, %error, "temporary room cleanup failed; record retained for retry");
                }
            }
        }
    }

    fn observe(
        &self,
        guild: GuildId,
        user: UserId,
        channel: Option<ChannelId>,
    ) -> Option<Option<ChannelId>> {
        let mut all = self.occupants.lock().unwrap();
        let members = all.get_mut(&guild)?;
        Some(match channel {
            Some(channel) => members.insert(user, channel),
            None => members.remove(&user),
        })
    }

    pub(super) async fn update(
        &self,
        ctx: &Context,
        store: &Store,
        guild: GuildId,
        new: &VoiceState,
    ) {
        // Update before awaiting network work so other occupants remain visible during creation/deletion.
        let Some(previous) = self.observe(guild, new.user_id, new.channel_id) else {
            return;
        };
        if previous == new.channel_id {
            return;
        }
        let _guard = self.operations.lock().await;
        if let Some(channel) = previous {
            self.cleanup(ctx, store, guild, channel).await;
        }
        let Some(source) = new.channel_id else {
            return;
        };
        if creator(store, guild) != Some(source)
            || self.channel(guild, new.user_id) != Some(source)
            || !feature_enabled(store, &guild.to_string(), "utility.temp_channels", None)
        {
            return;
        }
        if let Err(error) = self.create_room(ctx, store, guild, source, new).await {
            warn!(%guild, user = %new.user_id, %error, "temporary room creation or move failed");
        }
    }

    async fn create_room(
        &self,
        ctx: &Context,
        store: &Store,
        guild: GuildId,
        source: ChannelId,
        state: &VoiceState,
    ) -> Result<()> {
        let member = match &state.member {
            Some(member) => member.clone(),
            None => guild.member(&ctx.http, state.user_id).await?,
        };
        if member.user.bot {
            return Ok(());
        }
        let guild_text = guild.to_string();
        let channels = guild.channels(&ctx.http).await?;
        let hub = channels
            .get(&source)
            .filter(|channel| channel.kind == ChannelType::Voice)
            .ok_or_else(|| anyhow::anyhow!("creator channel missing or not voice"))?;
        let template = setting_string(store, &guild_text, "utility.temp_channels.name_template")
            .unwrap_or_else(|| "{user}'s room".into());
        let decision = evaluate_temp_channel(
            &template,
            member.display_name(),
            store.active_temp_channels(&guild_text)?.max(0) as u64,
            setting_u64(store, &guild_text, "utility.temp_channels.max_active", 10),
        );
        if !decision.allowed {
            return Ok(());
        }
        if self.channel(guild, state.user_id) != Some(source) {
            return Ok(());
        }
        let mut create = CreateChannel::new(decision.room_name)
            .kind(ChannelType::Voice)
            .permissions(hub.permission_overwrites.clone());
        if let Some(category) = hub.parent_id {
            create = create.category(category);
        }
        let room = guild.create_channel(&ctx.http, create).await?;
        // Persist before moving: failed moves/deletes remain recoverable after reconnect.
        if let Err(error) = store.register_temp_channel(
            &guild_text,
            &room.id.to_string(),
            &state.user_id.to_string(),
        ) {
            let _ = room.id.delete(&ctx.http).await;
            return Err(error);
        }
        if self.channel(guild, state.user_id) != Some(source) {
            self.cleanup(ctx, store, guild, room.id).await;
            return Ok(());
        }
        if let Err(error) = guild.move_member(&ctx.http, state.user_id, room.id).await {
            self.cleanup(ctx, store, guild, room.id).await;
            return Err(error.into());
        }
        let mut all = self.occupants.lock().unwrap();
        if let Some(members) = all.get_mut(&guild)
            && members.get(&state.user_id) == Some(&source)
        {
            members.insert(state.user_id, room.id);
        }
        Ok(())
    }

    pub(super) async fn setup(
        &self,
        ctx: &Context,
        store: &Store,
        guild: GuildId,
    ) -> Result<ChannelId> {
        let _guard = self.operations.lock().await;
        let channels = guild.channels(&ctx.http).await?;
        if let Some(id) = creator(store, guild)
            && let Some(channel) = channels.get(&id)
        {
            anyhow::ensure!(
                channel.kind == ChannelType::Voice,
                "recorded creator is not a voice channel"
            );
            return Ok(id);
        }
        let category = setting_string(
            store,
            &guild.to_string(),
            "utility.temp_channels.category_id",
        )
        .filter(|id| !id.is_empty())
        .map(|id| id.parse::<u64>())
        .transpose()?
        .map(ChannelId::new);
        let mut create = CreateChannel::new("➕ Creator Channel").kind(ChannelType::Voice);
        if let Some(id) = category {
            let category = channels
                .get(&id)
                .filter(|channel| channel.kind == ChannelType::Category)
                .ok_or_else(|| anyhow::anyhow!("configured temporary voice category missing"))?;
            create = create
                .category(id)
                .permissions(category.permission_overwrites.clone());
        }
        let channel = guild.create_channel(&ctx.http, create).await?;
        if let Err(error) = store.set_setting(
            &guild.to_string(),
            "utility.temp_channels.creator_channel_id",
            &channel.id.to_string(),
        ) {
            let _ = channel.id.delete(&ctx.http).await;
            return Err(error);
        }
        Ok(channel.id)
    }
}

fn creator(store: &Store, guild: GuildId) -> Option<ChannelId> {
    setting_string(
        store,
        &guild.to_string(),
        "utility.temp_channels.creator_channel_id",
    )
    .and_then(|id| id.parse::<u64>().ok())
    .filter(|id| *id != 0)
    .map(ChannelId::new)
}

fn missing_channel(error: &serenity::Error) -> bool {
    matches!(error, serenity::Error::Http(serenity::http::HttpError::UnsuccessfulRequest(response)) if response.error.code == 10003)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_updates_moves_and_missing_snapshots() {
        let state = TempChannels::default();
        let guild = GuildId::new(1);
        let user = UserId::new(2);
        let hub = ChannelId::new(3);
        assert_eq!(state.observe(guild, user, Some(hub)), None);
        state
            .occupants
            .lock()
            .unwrap()
            .insert(guild, HashMap::new());
        assert_eq!(state.observe(guild, user, Some(hub)), Some(None));
        assert_eq!(state.observe(guild, user, Some(hub)), Some(Some(hub)));
        assert_eq!(state.channel(guild, user), Some(hub));
        let room = ChannelId::new(4);
        assert_eq!(state.observe(guild, user, Some(room)), Some(Some(hub)));
        assert!(state.empty(guild, hub));
        assert!(!state.empty(guild, room));
        assert_eq!(state.observe(guild, user, None), Some(Some(room)));
        assert!(state.empty(guild, room));
    }

    #[test]
    fn room_lifecycle_counts_everyone_and_keeps_guilds_separate() {
        let state = TempChannels::default();
        let guild = GuildId::new(1);
        let room = ChannelId::new(3);
        let owner = UserId::new(10);
        let guest = UserId::new(11);
        assert!(
            !state.empty(guild, room),
            "unknown snapshot cannot prove empty"
        );
        state
            .occupants
            .lock()
            .unwrap()
            .insert(guild, HashMap::from([(owner, room), (guest, room)]));
        state
            .occupants
            .lock()
            .unwrap()
            .get_mut(&guild)
            .unwrap()
            .remove(&owner);
        assert!(
            !state.empty(guild, room),
            "owner departure must keep guest's room"
        );
        state
            .occupants
            .lock()
            .unwrap()
            .get_mut(&guild)
            .unwrap()
            .insert(guest, ChannelId::new(4));
        assert!(
            state.empty(guild, room),
            "last member moving away also empties room"
        );
        assert!(!state.empty(GuildId::new(2), room));
        state.forget(guild);
        assert!(
            !state.empty(guild, room),
            "unavailable guild cannot prove empty"
        );
    }
}
