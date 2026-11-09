use super::{
    ApiError, ApiState, Client, DISCORD_API_BASE, NICKNAME_SAVE_LOCK, SessionClaims, client_error,
    discord_json, feature_config_key, feature_key, guild_has_premium, require_auth,
    require_mutation_auth, runtime_projection_pairs,
};
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use helper_core::{NicknameAdapter, evaluate_nickname};
use serde_json::{Map, Value, json};
use std::{sync::Arc, time::Duration};

type ProfileError = (StatusCode, Json<ApiError>);
const IMAGE_LIMIT: usize = 2 * 1024 * 1024;

fn check_guild(state: &ApiState, claims: &SessionClaims, guild: &str) -> Result<(), ProfileError> {
    if claims.guild_id != guild
        || !guild.bytes().all(|byte| byte.is_ascii_digit())
        || guild.is_empty()
    {
        return Err(client_error(StatusCode::FORBIDDEN, "guild_not_managed"));
    }
    let managed = state
        .store
        .session_guilds(claims.session_id)
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?
        .into_iter()
        .any(|item| item.guild_id == guild);
    if !managed {
        return Err(client_error(StatusCode::FORBIDDEN, "guild_not_managed"));
    }
    Ok(())
}

fn discord_client() -> Result<Client, ProfileError> {
    Client::builder()
        .timeout(Duration::from_secs(8))
        .build()
        .map_err(|_| unavailable())
}

fn unavailable() -> ProfileError {
    client_error(StatusCode::BAD_GATEWAY, "bot_profile_unavailable")
}

async fn current_profile(
    client: &Client,
    auth: &str,
    guild: &str,
) -> Result<(Value, Value), ProfileError> {
    let user = discord_json(client, auth, "/users/@me")
        .await
        .map_err(|_| unavailable())?;
    let id = user["id"]
        .as_str()
        .filter(|id| !id.is_empty() && id.bytes().all(|b| b.is_ascii_digit()))
        .ok_or_else(unavailable)?;
    let member = discord_json(client, auth, &format!("/guilds/{guild}/members/{id}"))
        .await
        .map_err(|_| unavailable())?;
    Ok((user, member))
}

fn image_hash(value: &Value) -> Option<&str> {
    value.as_str().filter(|hash| {
        let hex = hash.strip_prefix("a_").unwrap_or(hash);
        hex.len() == 32 && hex.bytes().all(|byte| byte.is_ascii_hexdigit())
    })
}

fn profile(guild: &str, user: &Value, member: &Value, premium: bool) -> Value {
    let id = user["id"].as_str().unwrap_or_default();
    let avatar = image_hash(&member["avatar"]);
    let banner = image_hash(&member["banner"]);
    json!({
        "guildId": guild,
        "nick": member["nick"].as_str().unwrap_or_default(),
        "avatarUrl": avatar.map(|hash| format!("https://cdn.discordapp.com/guilds/{guild}/users/{id}/avatars/{hash}.png?size=256"))
            .or_else(|| image_hash(&user["avatar"]).map(|hash| format!("https://cdn.discordapp.com/avatars/{id}/{hash}.png?size=256"))),
        "bannerUrl": banner.map(|hash| format!("https://cdn.discordapp.com/guilds/{guild}/users/{id}/banners/{hash}.png?size=1024"))
            .or_else(|| image_hash(&user["banner"]).map(|hash| format!("https://cdn.discordapp.com/banners/{id}/{hash}.png?size=1024"))),
        "customAvatar": avatar.is_some(),
        "customBanner": banner.is_some(),
        "canEditImages": premium,
    })
}

// Discord decodes the image. Check the upload envelope and refuse animated PNGs before forwarding.
fn valid_image(value: &str) -> bool {
    let Some((kind, encoded)) = value.split_once(',') else {
        return false;
    };
    if encoded.len() > IMAGE_LIMIT.div_ceil(3) * 4 {
        return false;
    }
    let Ok(bytes) = STANDARD.decode(encoded) else {
        return false;
    };
    if bytes.len() > IMAGE_LIMIT {
        return false;
    }
    if kind == "data:image/jpeg;base64" {
        return bytes.starts_with(&[0xff, 0xd8, 0xff]) && bytes.ends_with(&[0xff, 0xd9]);
    }
    if kind != "data:image/png;base64"
        || !bytes.starts_with(b"\x89PNG\r\n\x1a\n")
        || bytes.get(12..16) != Some(b"IHDR")
    {
        return false;
    }
    let mut chunks = &bytes[8..];
    let mut has_image = false;
    while let Some(header) = chunks.get(..8) {
        let length = u32::from_be_bytes([header[0], header[1], header[2], header[3]]) as usize;
        let Some(rest) = length.checked_add(12).and_then(|end| chunks.get(end..)) else {
            return false;
        };
        match &header[4..8] {
            b"acTL" => return false,
            b"IDAT" => has_image = true,
            b"IEND" => return length == 0 && has_image && rest.is_empty(),
            _ => {}
        }
        chunks = rest;
    }
    false
}

fn validate_patch(mut fields: Map<String, Value>) -> Result<Map<String, Value>, ProfileError> {
    if fields.is_empty()
        || fields
            .keys()
            .any(|key| !matches!(key.as_str(), "nick" | "avatar" | "banner"))
    {
        return Err(client_error(StatusCode::BAD_REQUEST, "invalid_bot_profile"));
    }
    if let Some(value) = fields.get_mut("nick").filter(|value| !value.is_null()) {
        let nick = value
            .as_str()
            .ok_or_else(|| client_error(StatusCode::BAD_REQUEST, "invalid_nickname"))?;
        let decision = evaluate_nickname(&json!({"nickname": nick}));
        if !decision.allowed {
            return Err(client_error(StatusCode::BAD_REQUEST, "invalid_nickname"));
        }
        *value = if decision.nickname.is_empty() {
            Value::Null
        } else {
            Value::String(decision.nickname)
        };
    }
    for key in ["avatar", "banner"] {
        if fields
            .get(key)
            .is_some_and(|value| !value.is_null() && !value.as_str().is_some_and(valid_image))
        {
            return Err(client_error(
                StatusCode::BAD_REQUEST,
                "invalid_bot_profile_image",
            ));
        }
    }
    Ok(fields)
}

async fn patch_member(
    client: &Client,
    auth: &str,
    guild: &str,
    fields: &Map<String, Value>,
) -> Result<Value, ProfileError> {
    let response = client
        .patch(format!("{DISCORD_API_BASE}/guilds/{guild}/members/@me"))
        .header(header::AUTHORIZATION, auth)
        .json(fields)
        .send()
        .await
        .map_err(|_| unavailable())?;
    match response.status() {
        StatusCode::TOO_MANY_REQUESTS => Err(client_error(
            StatusCode::TOO_MANY_REQUESTS,
            "discord_rate_limited",
        )),
        StatusCode::FORBIDDEN => Err(client_error(
            StatusCode::FORBIDDEN,
            "bot_profile_permission",
        )),
        StatusCode::BAD_REQUEST => Err(client_error(
            StatusCode::BAD_REQUEST,
            "bot_profile_rejected",
        )),
        status if status.is_success() => response.json().await.map_err(|_| unavailable()),
        _ => Err(unavailable()),
    }
}

pub(super) async fn read(
    State(state): State<Arc<ApiState>>,
    Path(guild): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Value>, ProfileError> {
    let claims = require_auth(&state, &headers).await?;
    check_guild(&state, &claims, &guild)?;
    let client = discord_client()?;
    let auth = format!("Bot {}", state.discord_token);
    let (user, member) = current_profile(&client, &auth, &guild).await?;
    Ok(Json(profile(
        &guild,
        &user,
        &member,
        guild_has_premium(&state, &claims).await,
    )))
}

pub(super) async fn update(
    State(state): State<Arc<ApiState>>,
    Path(guild): Path<String>,
    headers: HeaderMap,
    Json(fields): Json<Map<String, Value>>,
) -> Result<Json<Value>, ProfileError> {
    let claims = require_mutation_auth(&state, &headers).await?;
    check_guild(&state, &claims, &guild)?;
    let fields = validate_patch(fields)?;
    let premium = guild_has_premium(&state, &claims).await;
    if !premium
        && ["avatar", "banner"]
            .iter()
            .any(|key| fields.get(*key).is_some_and(Value::is_string))
    {
        return Err(client_error(StatusCode::FORBIDDEN, "premium_required"));
    }
    let _nickname_guard = if fields.contains_key("nick") {
        Some(NICKNAME_SAVE_LOCK.lock().await)
    } else {
        None
    };
    let client = discord_client()?;
    let auth = format!("Bot {}", state.discord_token);
    let (user, before) = current_profile(&client, &auth, &guild).await?;
    let key = NicknameAdapter::KEY;
    let stored = if fields.contains_key("nick") {
        state
            .store
            .get_feature_setting(&guild, key)
            .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?
    } else {
        None
    };
    let member = patch_member(&client, &auth, &guild, &fields).await?;
    if fields.contains_key("nick") {
        let nickname = member["nick"].as_str().unwrap_or_default();
        let enabled = !nickname.is_empty();
        let mut config: Map<String, Value> = stored
            .as_ref()
            .and_then(|record| serde_json::from_str(&record.config_json).ok())
            .unwrap_or_default();
        config.insert("nickname".into(), json!(nickname));
        let config = Value::Object(config);
        let config_json = config.to_string();
        let mut projections = runtime_projection_pairs(key, &config);
        projections.extend([
            (feature_key(key), enabled.to_string()),
            (feature_config_key(key), config_json.clone()),
            ("identity.nickname.enabled".into(), enabled.to_string()),
        ]);
        let revision = stored.as_ref().map_or(0, |record| record.revision);
        if state
            .store
            .publish_feature_setting(
                &guild,
                key,
                enabled,
                &config_json,
                Some(revision),
                &claims.user_id,
                &projections,
            )
            .is_err()
        {
            let restore = Map::from_iter([("nick".to_owned(), before["nick"].clone())]);
            let _ = patch_member(&client, &auth, &guild, &restore).await;
            return Err(client_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "bot_profile_sync_failed",
            ));
        }
    }
    Ok(Json(profile(&guild, &user, &member, premium)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patch_preserves_omitted_fields_and_rejects_unknown_or_invalid_values() {
        let patch = |value: Value| validate_patch(value.as_object().unwrap().clone());
        let changes = patch(json!({"nick":"  Helper da comunidade  ", "banner":null})).unwrap();
        assert_eq!(changes["nick"], "Helper da comunidade");
        assert!(changes["banner"].is_null());
        assert!(!changes.contains_key("avatar"));
        assert!(patch(json!({"roles":["1"]})).is_err());
        assert!(patch(json!({"nick":"a".repeat(33)})).is_err());
        assert!(patch(json!({"avatar":"https://example.test/image.png"})).is_err());
        assert!(patch(json!({"banner":"data:image/png;base64,R0lGODlh"})).is_err());
        assert!(valid_image(
            "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+aZ1sAAAAASUVORK5CYII="
        ));
    }
}
