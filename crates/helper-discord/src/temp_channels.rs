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

    pub(super) async fn seed(&self, http: &serenity::http::Http, store: &Store, guild: &Guild) {
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
                    self.cleanup(http, store, guild.id, ChannelId::new(id))
                        .await;
                }
            }
        }
    }

    async fn cleanup(
        &self,
        http: &serenity::http::Http,
        store: &Store,
        guild: GuildId,
        channel: ChannelId,
    ) {
        if !self.empty(guild, channel) {
            return;
        }
        let Ok(Some(record)) = store.temp_channel(&channel.to_string()) else {
            return;
        };
        if record.guild_id != guild.to_string() || creator(store, guild) == Some(channel) {
            return;
        }
        match channel.delete(http).await {
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
        http: &serenity::http::Http,
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
            self.cleanup(http, store, guild, channel).await;
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
        if let Err(error) = self.create_room(http, store, guild, source, new).await {
            warn!(%guild, user = %new.user_id, %error, "temporary room creation or move failed");
        }
    }

    async fn create_room(
        &self,
        http: &serenity::http::Http,
        store: &Store,
        guild: GuildId,
        source: ChannelId,
        state: &VoiceState,
    ) -> Result<()> {
        let member = match &state.member {
            Some(member) => member.clone(),
            None => guild.member(http, state.user_id).await?,
        };
        if member.user.bot {
            return Ok(());
        }
        let guild_text = guild.to_string();
        let channels = guild.channels(http).await?;
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
        let room = guild.create_channel(http, create).await?;
        // Persist before moving: failed moves/deletes remain recoverable after reconnect.
        if let Err(error) = store.register_temp_channel(
            &guild_text,
            &room.id.to_string(),
            &state.user_id.to_string(),
        ) {
            let _ = room.id.delete(http).await;
            return Err(error);
        }
        if self.channel(guild, state.user_id) != Some(source) {
            self.cleanup(http, store, guild, room.id).await;
            return Ok(());
        }
        if let Err(error) = guild.move_member(http, state.user_id, room.id).await {
            self.cleanup(http, store, guild, room.id).await;
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
        http: &serenity::http::Http,
        store: &Store,
        guild: GuildId,
    ) -> Result<ChannelId> {
        let _guard = self.operations.lock().await;
        let channels = guild.channels(http).await?;
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
        let channel = guild.create_channel(http, create).await?;
        if let Err(error) = store.set_setting(
            &guild.to_string(),
            "utility.temp_channels.creator_channel_id",
            &channel.id.to_string(),
        ) {
            let _ = channel.id.delete(http).await;
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
    use serde_json::{Value, json};

    async fn mock_http(
        replies: Vec<(u16, Value)>,
    ) -> (serenity::http::Http, tokio::task::JoinHandle<Vec<String>>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            let mut requests = Vec::new();
            for (status, reply) in replies {
                let (mut socket, _) =
                    tokio::time::timeout(Duration::from_secs(5), listener.accept())
                        .await
                        .unwrap()
                        .unwrap();
                let mut request = Vec::new();
                loop {
                    let mut bytes = [0; 4096];
                    let count = socket.read(&mut bytes).await.unwrap();
                    assert!(count > 0);
                    request.extend_from_slice(&bytes[..count]);
                    if let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                        let headers = String::from_utf8_lossy(&request[..end]);
                        let length = headers
                            .lines()
                            .find_map(|line| {
                                line.to_lowercase()
                                    .strip_prefix("content-length:")
                                    .and_then(|v| v.trim().parse::<usize>().ok())
                            })
                            .unwrap_or(0);
                        if request.len() >= end + 4 + length {
                            break;
                        }
                    }
                    assert!(request.len() < 100_000);
                }
                requests.push(String::from_utf8(request).unwrap());
                let body = reply.to_string();
                socket.write_all(format!("HTTP/1.1 {status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
            }
            requests
        });
        (
            serenity::http::HttpBuilder::new("fixture-only")
                .proxy(base)
                .ratelimiter_disabled(true)
                .build(),
            task,
        )
    }

    fn voice_channel(id: u64) -> Value {
        json!({"id":id.to_string(),"guild_id":"1","name":"room","type":2,"permission_overwrites":[]})
    }

    fn fixture() -> (TempChannels, Store, VoiceState) {
        let state = TempChannels::default();
        let store = Store::open(":memory:").unwrap();
        store
            .set_setting("1", "feature.utility.temp_channels", "true")
            .unwrap();
        store
            .set_setting("1", "utility.temp_channels.creator_channel_id", "3")
            .unwrap();
        state
            .occupants
            .lock()
            .unwrap()
            .insert(GuildId::new(1), HashMap::new());
        let mut member = serenity::all::Member::default();
        member.nick = Some("Rexy".into());
        let mut voice: VoiceState = serde_json::from_value(json!({
            "user_id":"10", "guild_id":"1", "channel_id":"3", "session_id":"fixture",
            "deaf":false,"mute":false,"self_deaf":false,"self_mute":false,"suppress":false
        }))
        .unwrap();
        voice.member = Some(member);
        (state, store, voice)
    }

    #[tokio::test]
    async fn creator_setup_is_reused_and_never_registered_as_a_temporary_room() {
        let (state, store, _) = fixture();
        let (http, task) = mock_http(vec![
            (200, json!([])),
            (200, voice_channel(3)),
            (200, json!([voice_channel(3)])),
        ])
        .await;
        assert_eq!(
            state.setup(&http, &store, GuildId::new(1)).await.unwrap(),
            ChannelId::new(3)
        );
        assert_eq!(
            state.setup(&http, &store, GuildId::new(1)).await.unwrap(),
            ChannelId::new(3)
        );
        assert_eq!(store.active_temp_channels("1").unwrap(), 0);
        let requests = task.await.unwrap();
        assert!(requests[1].starts_with("POST /guilds/1/channels "));
        let body: Value =
            serde_json::from_str(requests[1].split("\r\n\r\n").nth(1).unwrap()).unwrap();
        assert_eq!(body["name"], "➕ Creator Channel");
        assert_eq!(body["type"], 2);
    }

    #[tokio::test]
    async fn joins_create_and_move_using_display_name_and_only_last_member_departure_deletes() {
        let (state, store, voice) = fixture();
        let (http, task) = mock_http(vec![(200, json!([voice_channel(3)])), (200, voice_channel(4)), (200, json!({"user":{"id":"10","username":"rexy0345","discriminator":"0"},"roles":[],"joined_at":null,"deaf":false,"mute":false})), (200, voice_channel(4))]).await;
        state.update(&http, &store, GuildId::new(1), &voice).await;
        assert_eq!(store.active_temp_channels("1").unwrap(), 1);
        assert_eq!(
            state.channel(GuildId::new(1), voice.user_id),
            Some(ChannelId::new(4))
        );
        state.observe(GuildId::new(1), UserId::new(11), Some(ChannelId::new(4)));
        let mut leave = voice.clone();
        leave.channel_id = None;
        state.update(&http, &store, GuildId::new(1), &leave).await;
        assert_eq!(
            store.active_temp_channels("1").unwrap(),
            1,
            "guest still inside"
        );
        leave.user_id = UserId::new(11);
        leave.channel_id = Some(ChannelId::new(8));
        state.update(&http, &store, GuildId::new(1), &leave).await;
        assert_eq!(store.active_temp_channels("1").unwrap(), 0);
        let requests = task.await.unwrap();
        assert!(requests[1].contains("Rexy's room"));
        assert!(requests[2].starts_with("PATCH /guilds/1/members/10 "));
        assert!(requests[2].contains("\"channel_id\":\"4\""));
        assert!(requests[3].starts_with("DELETE /channels/4 "));
        assert_eq!(creator(&store, GuildId::new(1)), Some(ChannelId::new(3)));
    }

    #[tokio::test]
    async fn failed_move_removes_the_new_empty_room_and_delete_failure_keeps_retry_record() {
        let (state, store, voice) = fixture();
        let denied = json!({"code":50013,"message":"Missing Permissions"});
        let (http, task) = mock_http(vec![
            (200, json!([voice_channel(3)])),
            (200, voice_channel(4)),
            (403, denied.clone()),
            (403, denied),
            (200, voice_channel(4)),
        ])
        .await;
        state.update(&http, &store, GuildId::new(1), &voice).await;
        assert_eq!(
            store.active_temp_channels("1").unwrap(),
            1,
            "failed delete remains durable"
        );
        state
            .cleanup(&http, &store, GuildId::new(1), ChannelId::new(4))
            .await;
        assert_eq!(store.active_temp_channels("1").unwrap(), 0);
        assert_eq!(task.await.unwrap().len(), 5);
    }

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
