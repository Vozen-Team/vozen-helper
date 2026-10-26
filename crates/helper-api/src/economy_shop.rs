use super::*;
use helper_store::ShopProductInput;
use serde_json::{Value, json};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct PageQuery {
    before: Option<i64>,
    guild_id: Option<String>,
}
fn scope(claims: &SessionClaims, query: &PageQuery) -> Result<(), (StatusCode, Json<ApiError>)> {
    if query.guild_id.as_deref() != Some(&claims.guild_id) {
        return Err(client_error(StatusCode::CONFLICT, "guild_changed"));
    }
    Ok(())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProductWrite {
    version: i64,
    product: ShopProductInput,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Version {
    version: i64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Resolve {
    status: String,
}

fn error(error: anyhow::Error) -> (StatusCode, Json<ApiError>) {
    match error.to_string().as_str() {
        "shop_changed" => client_error(StatusCode::CONFLICT, "shop_changed"),
        "shop_full" => client_error(StatusCode::BAD_REQUEST, "shop_full"),
        "shop_invalid_product" => client_error(StatusCode::BAD_REQUEST, "shop_invalid_product"),
        _ => client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"),
    }
}
pub(super) async fn get(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Query(query): Query<PageQuery>,
) -> Result<Response, (StatusCode, Json<ApiError>)> {
    let claims = require_auth(&state, &headers)?;
    scope(&claims, &query)?;
    let before = query.before.unwrap_or(i64::MAX);
    if before <= 0 {
        return Err(client_error(StatusCode::BAD_REQUEST, "invalid_cursor"));
    }
    let products = state.store.shop_products(&claims.guild_id).map_err(error)?;
    let orders = state
        .store
        .shop_orders(&claims.guild_id, before)
        .map_err(error)?;
    let next = if orders.len() == 50 {
        orders.last().map(|order| order.id)
    } else {
        None
    };
    let staff_channel = state
        .store
        .get_setting(&claims.guild_id, "community.economy.staff_channel")
        .map_err(error)?
        .unwrap_or_default();
    let failed_notices = state
        .store
        .failed_shop_notices(&claims.guild_id)
        .map_err(error)?;
    Ok(([(header::CACHE_CONTROL,"no-store")],Json(json!({"guildId":claims.guild_id,"products":products,"orders":orders,"nextCursor":next,"staffChannel":staff_channel,"failedNotices":failed_notices}))).into_response())
}

async fn validate_role(
    state: &ApiState,
    guild: &str,
    input: &ShopProductInput,
) -> Result<(), (StatusCode, Json<ApiError>)> {
    if input.delivery != "role" {
        return Ok(());
    }
    let role_id = input
        .role_id
        .as_deref()
        .ok_or_else(|| client_error(StatusCode::BAD_REQUEST, "shop_invalid_product"))?;
    let snapshot = fetch_discord_guild_snapshot(guild, &state.discord_token).await;
    if !snapshot.roles_ready || !snapshot.bot_ready {
        return Err(client_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "discord_context_unavailable",
        ));
    }
    let role = snapshot
        .roles
        .iter()
        .find(|role| role["id"].as_str() == Some(role_id))
        .ok_or_else(|| client_error(StatusCode::BAD_REQUEST, "shop_role_unavailable"))?;
    let configured = BTreeSet::from([("roleId".into(), role_id.into())]);
    let permissions = role["permissions"]
        .as_str()
        .and_then(|value| value.parse::<u64>().ok());
    if !permissions.is_some_and(helper_core::shop_role_permissions_safe)
        || !role_hierarchy_issues(guild, &snapshot.bot_role_ids, &snapshot.roles, &configured)
            .is_empty()
        || !effective_bot_permissions(guild, &snapshot.roles, &snapshot.bot_role_ids)
            .is_some_and(|p| p & ((1 << 28) | 8) != 0)
    {
        return Err(client_error(
            StatusCode::BAD_REQUEST,
            "shop_role_unavailable",
        ));
    }
    Ok(())
}
pub(super) async fn create(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Query(query): Query<PageQuery>,
    Json(input): Json<ShopProductInput>,
) -> Result<Json<Value>, (StatusCode, Json<ApiError>)> {
    let claims = require_mutation_auth(&state, &headers)?;
    scope(&claims, &query)?;
    validate_role(&state, &claims.guild_id, &input).await?;
    state
        .store
        .save_shop_product(&claims.guild_id, None, 0, &input)
        .map_err(error)?;
    Ok(Json(json!({"ok":true})))
}
pub(super) async fn update(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Query(query): Query<PageQuery>,
    Json(input): Json<ProductWrite>,
) -> Result<Json<Value>, (StatusCode, Json<ApiError>)> {
    let claims = require_mutation_auth(&state, &headers)?;
    scope(&claims, &query)?;
    validate_role(&state, &claims.guild_id, &input.product).await?;
    state
        .store
        .save_shop_product(&claims.guild_id, Some(id), input.version, &input.product)
        .map_err(error)?;
    Ok(Json(json!({"ok":true})))
}
pub(super) async fn remove(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Query(query): Query<PageQuery>,
    Json(input): Json<Version>,
) -> Result<Json<Value>, (StatusCode, Json<ApiError>)> {
    let claims = require_mutation_auth(&state, &headers)?;
    scope(&claims, &query)?;
    state
        .store
        .remove_shop_product(&claims.guild_id, id, input.version)
        .map_err(error)?;
    Ok(Json(json!({"ok":true})))
}
pub(super) async fn resolve(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Query(query): Query<PageQuery>,
    Json(input): Json<Resolve>,
) -> Result<Json<Value>, (StatusCode, Json<ApiError>)> {
    let claims = require_mutation_auth(&state, &headers)?;
    scope(&claims, &query)?;
    state
        .store
        .resolve_shop_order(&claims.guild_id, id, &input.status, &claims.user_id)
        .map_err(error)?;
    Ok(Json(json!({"ok":true})))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct NoticeSettings {
    channel_id: String,
}
fn notice_channel_allowed(snapshot: &DiscordGuildSnapshot, guild: &str, id: &str) -> bool {
    let Some(channel) = snapshot
        .channels
        .iter()
        .find(|channel| channel["id"].as_str() == Some(id))
    else {
        return false;
    };
    if !matches!(channel["type"].as_u64(), Some(0 | 5)) {
        return false;
    }
    let Some(base) = effective_bot_permissions(guild, &snapshot.roles, &snapshot.bot_role_ids)
    else {
        return false;
    };
    if base & 8 != 0 {
        return true;
    }
    snapshot
        .bot_user_id
        .as_deref()
        .and_then(|bot| {
            channel_bot_permissions(
                base,
                guild,
                bot,
                &snapshot.bot_role_ids,
                &channel["permission_overwrites"],
            )
        })
        .is_some_and(|bits| {
            [10, 11, 14]
                .into_iter()
                .all(|bit| permission_bitfield_has(bits, bit))
        })
}
pub(super) async fn settings(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Query(query): Query<PageQuery>,
    Json(input): Json<NoticeSettings>,
) -> Result<Json<Value>, (StatusCode, Json<ApiError>)> {
    let claims = require_mutation_auth(&state, &headers)?;
    scope(&claims, &query)?;
    if !input.channel_id.is_empty() {
        if !input.channel_id.parse::<u64>().is_ok_and(|id| id > 0) {
            return Err(client_error(
                StatusCode::BAD_REQUEST,
                "shop_invalid_channel",
            ));
        }
        let snapshot = fetch_discord_guild_snapshot(&claims.guild_id, &state.discord_token).await;
        if !snapshot.channels_ready || !snapshot.roles_ready || !snapshot.bot_ready {
            return Err(client_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "discord_context_unavailable",
            ));
        }
        if !notice_channel_allowed(&snapshot, &claims.guild_id, &input.channel_id) {
            return Err(client_error(
                StatusCode::BAD_REQUEST,
                "shop_invalid_channel",
            ));
        }
    }
    state
        .store
        .set_setting(
            &claims.guild_id,
            "community.economy.staff_channel",
            &input.channel_id,
        )
        .map_err(error)?;
    Ok(Json(json!({"ok":true})))
}
#[cfg(test)]
mod notice_tests {
    use super::*;
    #[test]
    fn staff_channel_checks_type_membership_and_channel_overwrites() {
        let bits = (1u64 << 10) | (1 << 11) | (1 << 14);
        let mut snapshot = DiscordGuildSnapshot {
            channels: vec![json!({"id":"20","type":0,"permission_overwrites":[]})],
            roles: vec![json!({"id":"10","permissions":bits.to_string()})],
            bot_user_id: Some("30".into()),
            bot_role_ids: vec![],
            channels_ready: true,
            roles_ready: true,
            bot_ready: true,
            bot_reason: None,
            stale_reason: None,
        };
        assert!(notice_channel_allowed(&snapshot, "10", "20"));
        assert!(!notice_channel_allowed(&snapshot, "10", "21"));
        snapshot.channels[0]["type"] = json!(2);
        assert!(!notice_channel_allowed(&snapshot, "10", "20"));
        snapshot.channels[0]["type"] = json!(0);
        snapshot.channels[0]["permission_overwrites"] =
            json!([{"id":"30","type":1,"allow":"0","deny":(1u64<<11).to_string()}]);
        assert!(!notice_channel_allowed(&snapshot, "10", "20"));
    }
}
