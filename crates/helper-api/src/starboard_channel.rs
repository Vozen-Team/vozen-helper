//! Explicit creation only: never changes permissions on an existing user channel.
use super::*;
use serde_json::{Value, json};

static CREATE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
#[derive(Clone, Copy)]
enum ChannelPurpose {
    Starboard,
    TicketPanel,
}

impl ChannelPurpose {
    fn record(self) -> &'static str {
        match self {
            Self::Starboard => "community.starboard.created_channel",
            Self::TicketPanel => "support.tickets.created_panel_channel",
        }
    }
    fn payload(self, guild: &str, bot: &str, name: &str, staff: &[String]) -> Value {
        let mut payload = channel_payload(
            guild,
            bot,
            name,
            match self {
                Self::Starboard => staff,
                Self::TicketPanel => &[],
            },
        );
        if matches!(self, Self::TicketPanel) {
            payload["topic"] = json!(
                "Vozen Helper • Open a private support ticket using the panel below. Read-only for members; administrators retain access."
            );
        }
        payload
    }
}
const READ: u64 = (1 << 6) | (1 << 10) | (1 << 16);
const SEND: u64 = 1 << 11;
// Denying SEND already implicitly denies SEND_TTS_MESSAGES. Including TTS
// explicitly makes Discord reject creation for bots without the TTS privilege.
const NO_CHAT: u64 = SEND | (1 << 35) | (1 << 36) | (1 << 38);
const BOT_ALLOW: u64 = READ | SEND | (1 << 14) | (1 << 15);
const CREATE_REQUIRED: u64 = BOT_ALLOW | NO_CHAT | 16 | (1 << 28);
const MODERATOR: u64 = 8 | 32 | (1 << 1) | (1 << 2) | (1 << 13) | (1 << 40);

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct CreateRequest {
    name: String,
    #[serde(default)]
    moderator_role_ids: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TicketCreateRequest {
    name: String,
}

pub(super) async fn create_ticket_panel(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Json(request): Json<TicketCreateRequest>,
) -> Result<Json<Value>, (StatusCode, Json<ApiError>)> {
    create_for(
        state,
        headers,
        CreateRequest {
            name: request.name,
            moderator_role_ids: vec![],
        },
        ChannelPurpose::TicketPanel,
    )
    .await
    .map_err(|(status, Json(mut error))| {
        error.code = error.code.replace("starboard_", "ticket_");
        error.message = error.message.replace("starboard_", "ticket_");
        (status, Json(error))
    })
}

fn channel_name(name: &str) -> Option<String> {
    let name = name.trim().to_ascii_lowercase();
    (name.len() >= 2
        && name.len() <= 80
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'))
    .then_some(name)
}

fn staff_role(role: &Value, guild: &str) -> bool {
    role["id"].as_str().is_some_and(|id| id != guild)
        && !role["managed"].as_bool().unwrap_or(false)
        && parse_permission_bits(role).is_some_and(|bits| bits & MODERATOR != 0)
}

fn channel_payload(guild: &str, bot: &str, name: &str, staff: &[String]) -> Value {
    let mut overwrites = vec![
        json!({"id":guild,"type":0,"allow":READ.to_string(),"deny":NO_CHAT.to_string()}),
        json!({"id":bot,"type":1,"allow":BOT_ALLOW.to_string(),"deny":"0"}),
    ];
    for role in staff {
        overwrites.push(json!({"id":role,"type":0,"allow":SEND.to_string(),"deny":"0"}));
    }
    json!({"name":name,"type":0,"topic":"Community highlights • Vozen Starboard. Read-only for members; moderators can post.","permission_overwrites":overwrites})
}

fn matching_permissions(channel: &Value, payload: &Value) -> bool {
    let Some(actual) = channel["permission_overwrites"].as_array() else {
        return false;
    };
    let Some(expected) = payload["permission_overwrites"].as_array() else {
        return false;
    };
    actual.len() == expected.len()
        && expected.iter().all(|wanted| {
            actual.iter().any(|item| {
                item["id"] == wanted["id"]
                    && item["type"] == wanted["type"]
                    && item["allow"] == wanted["allow"]
                    && (item["deny"] == wanted["deny"]
                        // Older protected channels also denied TTS explicitly.
                        // Preserve them without rewriting their permissions.
                        || (wanted["type"] == 0
                            && wanted["deny"].as_str() == Some(&NO_CHAT.to_string())
                            && item["deny"].as_str() == Some(&(NO_CHAT | (1 << 12)).to_string())))
            })
        })
}

pub(super) async fn create(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Json(request): Json<CreateRequest>,
) -> Result<Json<Value>, (StatusCode, Json<ApiError>)> {
    create_for(state, headers, request, ChannelPurpose::Starboard).await
}

async fn create_for(
    state: Arc<ApiState>,
    headers: HeaderMap,
    request: CreateRequest,
    purpose: ChannelPurpose,
) -> Result<Json<Value>, (StatusCode, Json<ApiError>)> {
    let claims = require_mutation_auth(&state, &headers)?;
    let name = channel_name(&request.name)
        .ok_or_else(|| client_error(StatusCode::BAD_REQUEST, "starboard_invalid_channel_name"))?;
    if request.moderator_role_ids.len() > 20 {
        return Err(client_error(
            StatusCode::BAD_REQUEST,
            "starboard_too_many_staff_roles",
        ));
    }
    let _guard = CREATE_LOCK
        .try_lock()
        .map_err(|_| client_error(StatusCode::CONFLICT, "starboard_creation_busy"))?;
    if state.discord_token.len() < 20 {
        return Err(client_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "discord_adapter_unavailable",
        ));
    }
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(8))
        .build()
        .map_err(|_| client_error(StatusCode::SERVICE_UNAVAILABLE, "discord_unavailable"))?;
    let auth = format!("Bot {}", state.discord_token);
    let snapshot = fetch_discord_guild_snapshot(&claims.guild_id, &state.discord_token).await;
    if !snapshot.channels_ready || !snapshot.roles_ready || !snapshot.bot_ready {
        return Err(client_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "discord_context_unavailable",
        ));
    }
    // Revalidate the actor's membership and permissions, not just the OAuth snapshot.
    let guild = discord_json(&client, &auth, &format!("/guilds/{}", claims.guild_id))
        .await
        .map_err(|_| client_error(StatusCode::SERVICE_UNAVAILABLE, "discord_unavailable"))?;
    if guild["owner_id"].as_str() != Some(&claims.user_id) {
        let member = discord_json(
            &client,
            &auth,
            &format!("/guilds/{}/members/{}", claims.guild_id, claims.user_id),
        )
        .await
        .map_err(|_| client_error(StatusCode::FORBIDDEN, "guild_not_managed"))?;
        let roles: Vec<String> = member["roles"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect();
        let bits =
            effective_bot_permissions(&claims.guild_id, &snapshot.roles, &roles).unwrap_or(0);
        if bits & 8 == 0 && bits & (32 | 16) != (32 | 16) {
            return Err(client_error(
                StatusCode::FORBIDDEN,
                "starboard_user_manage_channels_required",
            ));
        }
    }
    let bits = effective_bot_permissions(&claims.guild_id, &snapshot.roles, &snapshot.bot_role_ids)
        .unwrap_or(0);
    if bits & 8 == 0 && bits & CREATE_REQUIRED != CREATE_REQUIRED {
        return Err(client_error(
            StatusCode::FORBIDDEN,
            "starboard_bot_permissions_required",
        ));
    }
    if snapshot.roles.iter().any(|role| {
        role["id"].as_str() == Some(&claims.guild_id)
            && parse_permission_bits(role).is_none_or(|bits| bits & 8 != 0)
    }) {
        return Err(client_error(
            StatusCode::CONFLICT,
            "starboard_everyone_administrator",
        ));
    }
    let staff: Vec<String> = if matches!(purpose, ChannelPurpose::TicketPanel) {
        vec![]
    } else if request.moderator_role_ids.is_empty() {
        snapshot
            .roles
            .iter()
            .filter(|role| staff_role(role, &claims.guild_id))
            .filter_map(|role| role["id"].as_str().map(str::to_owned))
            .collect()
    } else {
        request
            .moderator_role_ids
            .into_iter()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    };
    if staff.len() > 20
        || staff.iter().any(|id| {
            !snapshot
                .roles
                .iter()
                .any(|role| role["id"].as_str() == Some(id) && staff_role(role, &claims.guild_id))
        })
    {
        return Err(client_error(
            StatusCode::BAD_REQUEST,
            "starboard_invalid_staff_role",
        ));
    }
    let bot = snapshot.bot_user_id.as_deref().ok_or_else(|| {
        client_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "discord_context_unavailable",
        )
    })?;
    let payload = purpose.payload(&claims.guild_id, bot, &name, &staff);
    let saved = state
        .store
        .get_setting(&claims.guild_id, purpose.record())
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?
        .and_then(|raw| serde_json::from_str::<Value>(&raw).ok());
    if let Some(saved) = saved
        && let Some(channel) = snapshot
            .channels
            .iter()
            .find(|channel| channel["id"] == saved["id"])
    {
        if channel["type"].as_u64() != Some(0)
            || channel["name"].as_str() != Some(&name)
            || !matching_permissions(channel, &payload)
        {
            return Err(client_error(
                StatusCode::CONFLICT,
                "starboard_existing_channel_changed",
            ));
        }
        return Ok(Json(
            json!({"guildId":claims.guild_id,"channel":channel,"reused":true}),
        ));
    }
    if snapshot
        .channels
        .iter()
        .any(|channel| channel["name"].as_str() == Some(&name))
    {
        return Err(client_error(
            StatusCode::CONFLICT,
            "starboard_channel_name_exists",
        ));
    }
    let response = client
        .post(format!(
            "{DISCORD_API_BASE}/guilds/{}/channels",
            claims.guild_id
        ))
        .header(header::AUTHORIZATION, &auth)
        .header(
            "X-Audit-Log-Reason",
            match purpose {
                ChannelPurpose::Starboard => "Vozen%20Starboard%20read-only%20channel",
                ChannelPurpose::TicketPanel => "Vozen%20Tickets%20public%20panel%20channel",
            },
        )
        .json(&payload)
        .send()
        .await
        .map_err(|_| client_error(StatusCode::BAD_GATEWAY, "starboard_creation_uncertain"))?;
    if !response.status().is_success() {
        let status = response.status();
        let discord_code = response
            .json::<Value>()
            .await
            .ok()
            .and_then(|body| body["code"].as_u64());
        tracing::warn!(
            status = status.as_u16(),
            ?discord_code,
            "starboard channel creation rejected by Discord"
        );
        return Err(client_error(
            if status.as_u16() == 429 {
                StatusCode::TOO_MANY_REQUESTS
            } else {
                StatusCode::BAD_GATEWAY
            },
            match status.as_u16() {
                403 => "starboard_bot_permissions_required",
                429 => "starboard_creation_rate_limited",
                _ if discord_code == Some(30013) => "starboard_channel_limit_reached",
                _ => "discord_channel_create_failed",
            },
        ));
    }
    let channel = response
        .json::<Value>()
        .await
        .map_err(|_| client_error(StatusCode::BAD_GATEWAY, "starboard_creation_uncertain"))?;
    let id = channel["id"]
        .as_str()
        .ok_or_else(|| client_error(StatusCode::BAD_GATEWAY, "starboard_creation_uncertain"))?;
    if channel["type"].as_u64() != Some(0)
        || channel["guild_id"].as_str() != Some(&claims.guild_id)
        || !matching_permissions(&channel, &payload)
    {
        return Err(client_error(
            StatusCode::BAD_GATEWAY,
            "starboard_channel_permissions_unconfirmed",
        ));
    }
    state
        .store
        .set_setting(
            &claims.guild_id,
            purpose.record(),
            &json!({"id":id}).to_string(),
        )
        .map_err(|_| {
            client_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "starboard_channel_created_not_recorded",
            )
        })?;
    let _ = state.store.record_activity(
        &claims.guild_id,
        match purpose {
            ChannelPurpose::Starboard => "starboard_channel_created",
            ChannelPurpose::TicketPanel => "ticket_panel_channel_created",
        },
        &claims.user_id,
        Some(id),
        Some(&claims.user_id),
        &json!({"channelId":id,"moderatorRoleIds":staff}).to_string(),
    );
    Ok(Json(
        json!({"guildId":claims.guild_id,"channel":channel,"reused":false}),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ticket_panel_channel_is_public_read_only_and_uses_an_independent_record() {
        let purpose = ChannelPurpose::TicketPanel;
        assert_ne!(purpose.record(), ChannelPurpose::Starboard.record());
        let payload = purpose.payload("guild", "bot", "tickets", &["mod".into()]);
        assert!(payload["topic"].as_str().unwrap().contains("ticket"));
        assert_eq!(payload["type"], 0);
        let overwrites = &payload["permission_overwrites"];
        assert_eq!(
            overwrites.as_array().unwrap().len(),
            2,
            "no automatic staff posting overrides for the public panel"
        );
        let member = channel_bot_permissions(
            READ | SEND | NO_CHAT,
            "guild",
            "user",
            &["mod".into()],
            overwrites,
        )
        .unwrap();
        assert_eq!(member & READ, READ);
        assert_eq!(member & NO_CHAT, 0);
        let bot = channel_bot_permissions(0, "guild", "bot", &[], overwrites).unwrap();
        assert_eq!(bot & BOT_ALLOW, BOT_ALLOW);
        assert!(matching_permissions(&payload, &payload));
        assert!(!matching_permissions(
            &json!({"permission_overwrites":[]}),
            &payload
        ));
    }

    #[test]
    fn starboard_channel_policy_blocks_member_chat_threads_and_allows_bot_and_mod() {
        let payload = channel_payload("guild", "bot", "starboard", &["mod".into()]);
        let overwrites = &payload["permission_overwrites"];
        let members =
            channel_bot_permissions(READ | SEND | NO_CHAT, "guild", "member", &[], overwrites)
                .unwrap();
        assert_eq!(members & NO_CHAT, 0);
        assert_eq!(members & READ, READ);
        let moderator =
            channel_bot_permissions(READ | SEND, "guild", "member", &["mod".into()], overwrites)
                .unwrap();
        assert_ne!(moderator & SEND, 0);
        let bot = channel_bot_permissions(0, "guild", "bot", &[], overwrites).unwrap();
        assert_eq!(bot & BOT_ALLOW, BOT_ALLOW);
        assert_eq!(payload["type"], 0);
    }
    #[test]
    fn starboard_staff_rejects_everyone_regular_and_managed_roles() {
        for role in [
            json!({"id":"guild","permissions":"8"}),
            json!({"id":"member","permissions":"2048"}),
            json!({"id":"bot","managed":true,"permissions":"8"}),
        ] {
            assert!(!staff_role(&role, "guild"));
        }
        assert!(staff_role(
            &json!({"id":"mod","permissions":(1_u64 << 13).to_string()}),
            "guild"
        ));
    }
    #[test]
    fn starboard_name_and_reuse_do_not_adopt_unprotected_channels() {
        assert_eq!(channel_name(" Starboard ").as_deref(), Some("starboard"));
        for name in ["", "a", "star board", "../starboard", "@everyone"] {
            assert!(channel_name(name).is_none());
        }
        let payload = channel_payload("guild", "bot", "starboard", &[]);
        assert!(matching_permissions(&payload, &payload));
        assert!(!matching_permissions(
            &json!({"permission_overwrites":[]}),
            &payload
        ));
        let mut altered = payload.clone();
        altered["permission_overwrites"][0]["deny"] = json!("0");
        assert!(!matching_permissions(&altered, &payload));
        let mut legacy = payload.clone();
        legacy["permission_overwrites"][0]["deny"] = json!((NO_CHAT | (1 << 12)).to_string());
        assert!(matching_permissions(&legacy, &payload));
    }
    #[test]
    fn starboard_creation_needs_every_overwrite_bit_but_not_tts() {
        let payload = channel_payload("guild", "bot", "starboard", &["mod".into()]);
        for overwrite in payload["permission_overwrites"].as_array().unwrap() {
            let allow = overwrite["allow"].as_str().unwrap().parse::<u64>().unwrap();
            let deny = overwrite["deny"].as_str().unwrap().parse::<u64>().unwrap();
            assert_eq!((allow | deny) & !CREATE_REQUIRED, 0);
        }
        assert_eq!(CREATE_REQUIRED & (1 << 12), 0);
        for bit in [1 << 35, 1 << 36, 1 << 38] {
            assert_ne!(CREATE_REQUIRED & bit, 0);
        }
    }
}
