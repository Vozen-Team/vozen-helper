use super::*;
use serde_json::{Value, json};

#[derive(Deserialize)]
pub(super) struct PageQuery {
    limit: Option<u32>,
}

pub(super) async fn list(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Query(query): Query<PageQuery>,
) -> Result<Response, (StatusCode, Json<ApiError>)> {
    let claims = require_auth(&state, &headers).await?;
    let records = state
        .store
        .pending_reminders(&claims.guild_id, query.limit.unwrap_or(100))
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?;
    let reminders: Vec<Value> = records.into_iter().map(|record| {
        let payload: Value = serde_json::from_str(&record.payload).unwrap_or(Value::Null);
        // The existing scheduler keeps failed deliveries queued until a later poll.
        json!({
            "id": record.id, "targetId": record.target_id, "executeAt": record.execute_at,
            "channelId": payload["channel_id"].as_str(),
            "text": payload["text"].as_str().unwrap_or_default(),
            "repeat": payload["repeat"].as_str(), "remaining": payload["remaining"].as_u64(),
            "timezone": payload["timezone"].as_str(), "localTime": payload["local_time"].as_str(),
            "status": "pending", "attempts": 0
        })
    }).collect();
    Ok((
        [(header::CACHE_CONTROL, "no-store")],
        Json(json!({
            "guildId": claims.guild_id,
            "enabled": feature_enabled(&state, &claims.guild_id, "utility.reminders"),
            "reminders": reminders
        })),
    )
        .into_response())
}

pub(super) async fn cancel(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Json<Value>, (StatusCode, Json<ApiError>)> {
    let claims = require_mutation_auth(&state, &headers).await?;
    if id <= 0 {
        return Err(client_error(StatusCode::BAD_REQUEST, "invalid_reminder_id"));
    }
    if !state
        .store
        .cancel_reminder(&claims.guild_id, id)
        .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?
    {
        return Err(client_error(StatusCode::NOT_FOUND, "reminder_not_found"));
    }
    Ok(Json(json!({"ok": true, "id": id})))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{Body, to_bytes},
        http::Request,
    };
    use tower::ServiceExt;

    #[tokio::test]
    async fn reminder_routes_preserve_queue_and_enforce_guild_and_origin() {
        let store = Store::open(":memory:").unwrap();
        let session = crate::tests::claims("guild-a");
        store.save_session(&session).unwrap();
        let token = sign_session(&session, "test-session-secret-with-at-least-32-bytes");
        let own = store.schedule("guild-a", "member", 3000, r#"{"channel_id":"channel","text":"Test","repeat":"daily","remaining":2,"timezone":"UTC"}"#).unwrap();
        let other = store
            .schedule("guild-b", "private", 1000, r#"{"text":"Secret"}"#)
            .unwrap();
        let event = store
            .schedule_typed("guild-a", "event_reminder", "event", 2000, "{}")
            .unwrap();
        store
            .schedule("guild-a", "member", 4000, "invalid legacy payload")
            .unwrap();
        let mut state = crate::tests::state(store.clone());
        state.allowed_origin = Some("https://bot.example.com".into());
        let app = router(state);
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/reminders")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/reminders?limit=1")
                    .header(header::COOKIE, format!("vh_session={token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        let body: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 10000).await.unwrap()).unwrap();
        assert_eq!(body["guildId"], "guild-a");
        assert_eq!(body["reminders"].as_array().unwrap().len(), 1);
        assert_eq!(body["reminders"][0]["id"], own);
        assert_eq!(body["reminders"][0]["text"], "Test");
        assert_eq!(body["reminders"][0]["remaining"], 2);
        assert_eq!(store.due_scheduled_actions(5000, 100).unwrap().len(), 4);
        for (id, origin, expected) in [
            (own, false, StatusCode::FORBIDDEN),
            (other, true, StatusCode::NOT_FOUND),
            (event, true, StatusCode::NOT_FOUND),
            (own, true, StatusCode::OK),
        ] {
            let mut request = Request::builder()
                .method("DELETE")
                .uri(format!("/api/reminders/{id}"))
                .header(header::COOKIE, format!("vh_session={token}"));
            if origin {
                request = request.header(header::ORIGIN, "https://bot.example.com");
            }
            let response = app
                .clone()
                .oneshot(request.body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), expected);
        }
        let remaining = store.due_scheduled_actions(5000, 100).unwrap();
        assert_eq!(remaining.len(), 3);
        assert!(remaining.iter().any(|job| job.0 == other));
        assert!(remaining.iter().any(|job| job.0 == event));
        assert!(
            store
                .pending_reminders("guild-a", 100)
                .unwrap()
                .iter()
                .all(|job| job.id != own)
        );
    }
}
