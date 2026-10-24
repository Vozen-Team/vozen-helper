use super::*;

pub(super) async fn page(
    State(state): State<Arc<ApiState>>,
    Path(guild): Path<String>,
    headers: HeaderMap,
) -> Result<Response, (StatusCode, Json<ApiError>)> {
    if guild.len() < 15
        || guild.len() > 22
        || !guild.bytes().all(|b| b.is_ascii_digit())
        || !feature_enabled(&state, &guild, "community.achievements")
    {
        return Err(client_error(
            StatusCode::NOT_FOUND,
            "achievements_unavailable",
        ));
    }
    let now = Utc::now().timestamp();
    let token = match headers.get(header::AUTHORIZATION) {
        Some(value) => Some(
            value
                .to_str()
                .ok()
                .and_then(|value| value.strip_prefix("Achievement "))
                .ok_or_else(|| {
                    client_error(StatusCode::UNAUTHORIZED, "achievement_link_expired")
                })?,
        ),
        None => None,
    };
    let profile = if let Some(token) = token {
        Some(
            state
                .store
                .achievement_link(&guild, token, now)
                .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?
                .ok_or_else(|| {
                    client_error(StatusCode::UNAUTHORIZED, "achievement_link_expired")
                })?,
        )
    } else {
        None
    };
    let rows = state
        .store
        .achievement_progress(
            &guild,
            profile.as_ref().map_or("", |row| row.0.as_str()),
            now,
        )
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?;
    let (members, counts) = state
        .store
        .achievement_statistics(&guild)
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?;
    let statistics = rows
        .iter()
        .map(|row| {
            let counts = row
                .thresholds
                .iter()
                .enumerate()
                .map(|(index, _)| {
                    let key = if row.id == "xp" {
                        ["first_steps", "regular", "community_pillar"][index].to_string()
                    } else {
                        format!("{}:{}", row.id, index + 1)
                    };
                    counts.get(&key).copied().unwrap_or(0)
                })
                .collect::<Vec<_>>();
            (row.id.clone(), counts)
        })
        .collect::<BTreeMap<_, _>>();
    let name = state
        .store
        .get_setting(&guild, "community.achievements.guild_name")
        .ok()
        .flatten();
    let body = serde_json::json!({"guildId":guild,"guildName":name,"profile":profile.map(|(_,name,avatar)| serde_json::json!({"name":name,"avatar":avatar})),"achievements":rows,"trackedMembers":members,"tierCounts":statistics});
    let mut response = Json(body).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{Body, to_bytes},
        http::Request,
    };
    use tower::ServiceExt;
    const GUILD: &str = "1524199248248176751";
    #[tokio::test]
    async fn catalog_has_no_member_identifiers_and_profile_needs_scoped_live_token() {
        let store = Store::open(":memory:").unwrap();
        store
            .set_setting(GUILD, "feature.community.achievements", "true")
            .unwrap();
        store
            .record_achievement_event(GUILD, "private-member-id", "messages", "one")
            .unwrap();
        let token = store
            .create_achievement_link(
                GUILD,
                "private-member-id",
                "Member",
                "",
                Utc::now().timestamp(),
            )
            .unwrap();
        let app = router(super::super::tests::state(store.clone()));
        for (credential, expected) in [
            (None, StatusCode::OK),
            (Some("invalid"), StatusCode::UNAUTHORIZED),
            (Some(token.as_str()), StatusCode::OK),
        ] {
            let mut request = Request::builder().uri(format!("/api/achievements/{GUILD}"));
            if let Some(token) = credential {
                request = request.header(header::AUTHORIZATION, format!("Achievement {token}"));
            }
            let response = app
                .clone()
                .oneshot(request.body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), expected);
            if expected == StatusCode::OK {
                assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
                let body = String::from_utf8(
                    to_bytes(response.into_body(), 100_000)
                        .await
                        .unwrap()
                        .to_vec(),
                )
                .unwrap();
                assert!(!body.contains("private-member-id"));
                let value: serde_json::Value = serde_json::from_str(&body).unwrap();
                assert_eq!(
                    value["achievements"][0]["value"],
                    if credential.is_some() { 1 } else { 0 }
                );
                assert_eq!(value["profile"].is_null(), credential.is_none());
            }
        }
        store
            .set_setting(GUILD, "feature.community.achievements", "false")
            .unwrap();
        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/api/achievements/{GUILD}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert!(
            store
                .achievements_for(GUILD, "private-member-id")
                .unwrap()
                .is_empty(),
            "GET must not unlock or grant rewards"
        );
    }
}
