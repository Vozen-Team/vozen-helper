use super::*;

#[derive(Deserialize)]
pub(super) struct QueryOptions {
    category: Option<String>,
    before: Option<String>,
    limit: Option<u32>,
}

fn cursor(raw: Option<&str>) -> Result<Option<(i64, i64, i64)>, ()> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    let parts = raw
        .split(':')
        .map(str::parse::<i64>)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ())?;
    if parts.len() != 3 || parts[0] < 0 || !(0..=2).contains(&parts[1]) || parts[2] < 1 {
        return Err(());
    }
    Ok(Some((parts[0], parts[1], parts[2])))
}

pub(super) async fn get(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Query(query): Query<QueryOptions>,
) -> Result<Response, (StatusCode, Json<ApiError>)> {
    let claims = require_auth(&state, &headers).await?;
    let category = query.category.as_deref().unwrap_or("all");
    if !["all", "joins", "leaves", "bans", "timeouts", "helper"].contains(&category) {
        return Err(client_error(StatusCode::BAD_REQUEST, "invalid_category"));
    }
    let before = cursor(query.before.as_deref())
        .map_err(|_| client_error(StatusCode::BAD_REQUEST, "invalid_cursor"))?;
    let limit = query.limit.unwrap_or(50).clamp(1, 50);
    let mut rows = state
        .store
        .activity_feed(&claims.guild_id, category, before, limit + 1)
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?;
    let more = rows.len() > limit as usize;
    rows.truncate(limit as usize);
    let next = if more {
        rows.last().map(|row| row.cursor())
    } else {
        None
    };
    let ids = rows
        .iter()
        .flat_map(|row| std::iter::once(row.user_id.clone()).chain(row.actor_id.clone()))
        .filter(|id| !id.is_empty())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let names = discord_member_names(
        "https://discord.com/api/v10",
        &state.discord_token,
        &claims.guild_id,
        &ids,
    )
    .await;
    let mut events = Vec::new();
    for row in rows {
        let member_name = names
            .get(&row.user_id)
            .cloned()
            .or(row.user_tag.clone())
            .or_else(|| {
                state
                    .store
                    .activity_member_name(&claims.guild_id, &row.user_id)
                    .ok()
                    .flatten()
            });
        let actor_name = row.actor_id.as_ref().and_then(|id| {
            names.get(id).cloned().or_else(|| {
                state
                    .store
                    .activity_member_name(&claims.guild_id, id)
                    .ok()
                    .flatten()
            })
        });
        let mut value = serde_json::to_value(row)
            .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "encode_error"))?;
        value["memberName"] = serde_json::json!(member_name);
        value["actorName"] = serde_json::json!(actor_name);
        events.push(value);
    }
    Ok((
        [(header::CACHE_CONTROL, "no-store")],
        Json(serde_json::json!({"guildId":claims.guild_id,"events":events,"nextCursor":next})),
    )
        .into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cursors_are_bounded_numeric_ordering_keys() {
        assert_eq!(cursor(Some("123:2:10")), Ok(Some((123, 2, 10))));
        assert_eq!(cursor(None), Ok(None));
        for raw in ["bad", "1:3:1", "1:0:0", "-1:0:1", "1:0:1:9", "1:0:1 OR 1=1"] {
            assert!(cursor(Some(raw)).is_err());
        }
    }
}
