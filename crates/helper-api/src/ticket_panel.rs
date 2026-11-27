use helper_store::Store;
use serde_json::{Value, json};

fn panel_body(config: &Value) -> Value {
    let title = config["panelTitle"].as_str().unwrap_or("Need support?");
    let description = config["panelDescription"]
        .as_str()
        .unwrap_or("Open a private ticket and the support team will help you.");
    json!({
        "content": format!("**{title}**\n{description}"),
        "allowed_mentions": {"parse": []},
        "components": [{"type": 1, "components": [{"type": 2, "style": 1, "label": "Open ticket", "custom_id": "ticket:open"}]}]
    })
}

// The caller serializes ticket saves before checking the feature revision.
// References are per guild AND channel: switching back edits the original panel.
pub(super) async fn publish(
    store: &Store,
    token: &str,
    guild: &str,
    config: &Value,
    quota: u64,
    base: &str,
    recover_stale: bool,
) -> anyhow::Result<Value> {
    let Some(channel) = config["panelChannel"].as_str().filter(|id| !id.is_empty()) else {
        return Ok(Value::Null);
    };
    anyhow::ensure!(
        channel.parse::<u64>().is_ok_and(|id| id > 0),
        "invalid_panel_channel"
    );
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(8))
        .build()?;
    let authorization = format!("Bot {token}");
    let channel_url = format!("{base}/channels/{channel}");
    let channel_info: Value = client
        .get(&channel_url)
        .header("Authorization", &authorization)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    anyhow::ensure!(
        channel_info["guild_id"].as_str() == Some(guild),
        "panel_channel_wrong_guild"
    );
    anyhow::ensure!(
        matches!(channel_info["type"].as_u64(), Some(0 | 5)),
        "panel_channel_must_be_text"
    );
    let key = format!("support.ticket.dashboard_panel.{channel}");
    let mut record: Value = store
        .get_setting(guild, &key)?
        .map(|raw| serde_json::from_str(&raw))
        .transpose()?
        .unwrap_or(json!({}));
    let messages_url = format!("{channel_url}/messages");
    if record.as_object().is_some_and(|record| record.is_empty())
        && let Some(id) = store.ticket_panel_message(guild, channel)?
    {
        record = json!({"message_id": id});
        store.set_setting(guild, &key, &record.to_string())?;
    }
    let now = chrono::Utc::now().timestamp_millis();
    // Only an explicit repair may resolve an expired unknown delivery, and
    // only after the channel history was read: adopt the bot's own panel, or
    // post once when it is confirmed absent. A failed read changes nothing.
    if recover_stale
        && record["message_id"].is_null()
        && !record["nonce"].is_null()
        && now - record["started_at"].as_i64().unwrap_or(0) >= 120_000
    {
        if let Some(id) = find_bot_panel(&client, base, &authorization, channel).await? {
            record = json!({"message_id": id});
            store.set_setting(guild, &key, &record.to_string())?;
            store.set_setting(
                guild,
                &format!("support.panel.{id}"),
                &json!({"channel_id": channel, "message_id": id}).to_string(),
            )?;
        } else {
            store.delete_setting(guild, &key)?;
            record = json!({});
        }
    }
    let mut body = panel_body(config);
    if let Some(message) = record["message_id"].as_str() {
        anyhow::ensure!(message.parse::<u64>().is_ok(), "invalid_panel_reference");
        let response = client
            .patch(format!("{messages_url}/{message}"))
            .header("Authorization", &authorization)
            .json(&body)
            .send()
            .await?;
        if response.status().is_success() {
            return Ok(json!({"applied": true, "channelId": channel, "messageId": message}));
        }
        if response.status() != reqwest::StatusCode::NOT_FOUND {
            response.error_for_status()?;
        }
        // Only a confirmed missing message permits replacement. Never recreate
        // on a permission error, timeout, rate limit or server failure.
        store.delete_setting(guild, &format!("support.panel.{message}"))?;
        record = json!({});
    }
    anyhow::ensure!(
        store.count_settings_prefix(guild, "support.panel.")? < quota,
        "ticket_panel_quota_reached"
    );
    if record["nonce"].is_null() {
        record = json!({"nonce": uuid::Uuid::new_v4().simple().to_string()[..25].to_owned(), "started_at": now});
        store.set_setting(guild, &key, &record.to_string())?;
    } else {
        // Discord only deduplicates nonces for a few minutes. An older unknown
        // outcome must be inspected, not retried and potentially duplicated.
        anyhow::ensure!(
            now - record["started_at"].as_i64().unwrap_or(0) < 120_000,
            "ticket_panel_delivery_unknown_check_discord"
        );
    }
    body["nonce"] = record["nonce"].clone();
    body["enforce_nonce"] = json!(true);
    let response = client
        .post(&messages_url)
        .header("Authorization", &authorization)
        .json(&body)
        .send()
        .await?;
    if response.status().is_client_error()
        && response.status() != reqwest::StatusCode::REQUEST_TIMEOUT
    {
        store.delete_setting(guild, &key)?;
    }
    let message: Value = response.error_for_status()?.json().await?;
    let id = message["id"]
        .as_str()
        .filter(|id| id.parse::<u64>().is_ok())
        .ok_or_else(|| anyhow::anyhow!("invalid_panel_response"))?;
    store.set_setting(guild, &key, &json!({"message_id": id}).to_string())?;
    store.set_setting(
        guild,
        &format!("support.panel.{id}"),
        &json!({"channel_id": channel, "message_id": id}).to_string(),
    )?;
    Ok(json!({"applied": true, "channelId": channel, "messageId": id}))
}

// Looks for the bot's own ticket panel in the latest channel messages. The
// nonce is not trusted here: only the author and the open button identify it.
// Anything short of a clean read is an error, because `None` permits a post.
async fn find_bot_panel(
    client: &reqwest::Client,
    base: &str,
    authorization: &str,
    channel: &str,
) -> anyhow::Result<Option<String>> {
    let bot: Value = client
        .get(format!("{base}/users/@me"))
        .header("Authorization", authorization)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let bot_id = bot["id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("invalid_panel_response"))?;
    let history: Value = client
        .get(format!("{base}/channels/{channel}/messages?limit=50"))
        .header("Authorization", authorization)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let messages = history
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("invalid_panel_response"))?;
    let has_open_button = |message: &Value| {
        message["components"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|row| row["components"].as_array())
            .flatten()
            .any(|component| component["custom_id"].as_str() == Some("ticket:open"))
    };
    let Some(panel) = messages.iter().find(|message| {
        message["author"]["id"].as_str() == Some(bot_id) && has_open_button(message)
    }) else {
        return Ok(None);
    };
    let id = panel["id"]
        .as_str()
        .filter(|id| id.parse::<u64>().is_ok())
        .ok_or_else(|| anyhow::anyhow!("invalid_panel_response"))?;
    Ok(Some(id.to_owned()))
}

/// The stable codes `publish` reports; anything else is a generic failure.
pub(super) fn error_code(error: &anyhow::Error) -> &'static str {
    const CODES: [&str; 7] = [
        "invalid_panel_channel",
        "panel_channel_wrong_guild",
        "panel_channel_must_be_text",
        "invalid_panel_reference",
        "ticket_panel_quota_reached",
        "ticket_panel_delivery_unknown_check_discord",
        "invalid_panel_response",
    ];
    let message = error.to_string();
    CODES
        .into_iter()
        .find(|code| *code == message)
        .unwrap_or("ticket_panel_publish_failed")
}

#[cfg(test)]
mod tests {
    use super::*;

    type Reply = (&'static str, &'static str, u16, Value);
    type ReplyQueue = std::sync::Arc<std::sync::Mutex<std::collections::VecDeque<Reply>>>;

    #[tokio::test]
    async fn existing_slash_panel_is_adopted_even_when_quota_is_full() {
        let store = Store::open(":memory:").unwrap();
        store
            .set_setting(
                "10",
                "support.panel.30",
                r#"{"channel_id":"20","message_id":"30"}"#,
            )
            .unwrap();
        store
            .set_setting(
                "99",
                "support.panel.11",
                r#"{"channel_id":"20","message_id":"11"}"#,
            )
            .unwrap();
        assert_eq!(
            store.ticket_panel_message("10", "20").unwrap().as_deref(),
            Some("30")
        );
        assert_eq!(store.ticket_panel_message("10", "21").unwrap(), None);
        let (base, task, queue) = mock(vec![
            (
                "GET",
                "/channels/20",
                200,
                json!({"guild_id":"10", "type":0}),
            ),
            ("PATCH", "/channels/20/messages/30", 200, json!({"id":"30"})),
        ])
        .await;
        assert_eq!(
            publish(
                &store,
                "token",
                "10",
                &json!({"panelChannel":"20"}),
                1,
                &base,
                false
            )
            .await
            .unwrap()["messageId"],
            "30"
        );
        assert!(queue.lock().unwrap().is_empty());
        task.abort();
    }
    async fn mock(replies: Vec<Reply>) -> (String, tokio::task::JoinHandle<()>, ReplyQueue) {
        let queue: ReplyQueue = std::sync::Arc::new(std::sync::Mutex::new(replies.into()));
        let handler_queue = queue.clone();
        let app = axum::Router::new().fallback(move |request: axum::extract::Request| {
            let queue = handler_queue.clone();
            async move {
                let (method, path, status, body) = queue
                    .lock()
                    .unwrap()
                    .pop_front()
                    .expect("unexpected Discord request");
                assert_eq!(request.method().as_str(), method);
                assert_eq!(request.uri().path(), path);
                (
                    axum::http::StatusCode::from_u16(status).unwrap(),
                    axum::Json(body),
                )
            }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (base, task, queue)
    }

    #[tokio::test]
    async fn repeated_saves_edit_one_panel_and_keep_guild_isolation() {
        let store = Store::open(":memory:").unwrap();
        let channel = json!({"guild_id": "10", "type": 0});
        let (base, task, queue) = mock(vec![
            ("GET", "/channels/20", 200, channel.clone()),
            ("POST", "/channels/20/messages", 200, json!({"id":"30"})),
            ("GET", "/channels/20", 200, channel.clone()),
            ("PATCH", "/channels/20/messages/30", 200, json!({"id":"30"})),
            ("GET", "/channels/20", 200, channel),
        ])
        .await;
        let config = json!({"panelChannel":"20"});
        for _ in 0..2 {
            assert_eq!(
                publish(&store, "token", "10", &config, 1, &base, false)
                    .await
                    .unwrap()["messageId"],
                "30"
            );
        }
        assert!(
            publish(&store, "token", "99", &config, 1, &base, false)
                .await
                .is_err()
        );
        assert_eq!(
            store.count_settings_prefix("10", "support.panel.").unwrap(),
            1
        );
        assert_eq!(
            store.count_settings_prefix("99", "support.panel.").unwrap(),
            0
        );
        assert!(queue.lock().unwrap().is_empty());
        task.abort();
    }

    #[tokio::test]
    async fn only_confirmed_deleted_panel_is_replaced() {
        let store = Store::open(":memory:").unwrap();
        store
            .set_setting(
                "10",
                "support.ticket.dashboard_panel.20",
                r#"{"message_id":"30"}"#,
            )
            .unwrap();
        store.set_setting("10", "support.panel.30", "{}").unwrap();
        let channel = json!({"guild_id":"10", "type":0});
        let (base, task, queue) = mock(vec![
            ("GET", "/channels/20", 200, channel.clone()),
            ("PATCH", "/channels/20/messages/30", 403, json!({})),
            ("GET", "/channels/20", 200, channel),
            ("PATCH", "/channels/20/messages/30", 404, json!({})),
            ("POST", "/channels/20/messages", 200, json!({"id":"31"})),
        ])
        .await;
        let config = json!({"panelChannel":"20"});
        assert!(
            publish(&store, "token", "10", &config, 1, &base, false)
                .await
                .is_err()
        );
        assert_eq!(
            publish(&store, "token", "10", &config, 1, &base, false)
                .await
                .unwrap()["messageId"],
            "31"
        );
        assert!(
            store
                .get_setting("10", "support.panel.30")
                .unwrap()
                .is_none()
        );
        assert!(queue.lock().unwrap().is_empty());
        task.abort();
    }

    #[tokio::test]
    async fn quota_and_old_uncertain_delivery_do_not_post() {
        let store = Store::open(":memory:").unwrap();
        let channel = json!({"guild_id":"10", "type":0});
        let (base, task, queue) = mock(vec![
            ("GET", "/channels/20", 200, channel.clone()),
            ("GET", "/channels/20", 200, channel),
        ])
        .await;
        let config = json!({"panelChannel":"20"});
        assert!(
            publish(&store, "token", "10", &config, 0, &base, false)
                .await
                .is_err()
        );
        store
            .set_setting(
                "10",
                "support.ticket.dashboard_panel.20",
                r#"{"nonce":"old","started_at":1}"#,
            )
            .unwrap();
        assert!(
            publish(&store, "token", "10", &config, 1, &base, false)
                .await
                .is_err()
        );
        assert!(queue.lock().unwrap().is_empty());
        task.abort();
    }

    fn store_with_stale_delivery() -> Store {
        let store = Store::open(":memory:").unwrap();
        store
            .set_setting(
                "10",
                "support.ticket.dashboard_panel.20",
                r#"{"nonce":"old","started_at":1}"#,
            )
            .unwrap();
        store
    }

    fn stale_recovery_reads(history_status: u16, history: Value) -> Vec<Reply> {
        vec![
            (
                "GET",
                "/channels/20",
                200,
                json!({"guild_id":"10", "type":0}),
            ),
            ("GET", "/users/@me", 200, json!({"id":"99"})),
            ("GET", "/channels/20/messages", history_status, history),
        ]
    }

    #[tokio::test]
    async fn stale_delivery_adopts_the_bot_panel_on_recovery() {
        let store = store_with_stale_delivery();
        let open_button = json!([{"type":1,"components":[{"type":2,"custom_id":"ticket:open"}]}]);
        let history = json!([
            {"id":"33","author":{"id":"99"},"components":[]},
            {"id":"32","author":{"id":"77"},"components":open_button.clone()},
            {"id":"31","author":{"id":"99"},"components":open_button},
        ]);
        let mut replies = stale_recovery_reads(200, history);
        replies.push(("PATCH", "/channels/20/messages/31", 200, json!({"id":"31"})));
        let (base, task, queue) = mock(replies).await;
        let result = publish(
            &store,
            "token",
            "10",
            &json!({"panelChannel":"20"}),
            1,
            &base,
            true,
        )
        .await
        .unwrap();
        assert_eq!(result["messageId"], "31");
        assert!(
            store
                .get_setting("10", "support.panel.31")
                .unwrap()
                .is_some()
        );
        assert!(queue.lock().unwrap().is_empty());
        task.abort();
    }

    #[tokio::test]
    async fn stale_delivery_without_a_panel_posts_once_on_recovery() {
        let store = store_with_stale_delivery();
        let mut replies = stale_recovery_reads(200, json!([]));
        replies.push(("POST", "/channels/20/messages", 200, json!({"id":"32"})));
        let (base, task, queue) = mock(replies).await;
        let result = publish(
            &store,
            "token",
            "10",
            &json!({"panelChannel":"20"}),
            1,
            &base,
            true,
        )
        .await
        .unwrap();
        assert_eq!(result["messageId"], "32");
        assert!(queue.lock().unwrap().is_empty());
        task.abort();
    }

    #[tokio::test]
    async fn stale_delivery_stays_blocked_when_history_is_unreadable() {
        let store = store_with_stale_delivery();
        let (base, task, queue) = mock(stale_recovery_reads(403, json!({}))).await;
        assert!(
            publish(
                &store,
                "token",
                "10",
                &json!({"panelChannel":"20"}),
                1,
                &base,
                true,
            )
            .await
            .is_err()
        );
        let record: Value = serde_json::from_str(
            &store
                .get_setting("10", "support.ticket.dashboard_panel.20")
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(record["nonce"], "old");
        assert!(queue.lock().unwrap().is_empty());
        task.abort();
    }

    #[test]
    fn publish_errors_keep_their_specific_code() {
        for code in [
            "ticket_panel_delivery_unknown_check_discord",
            "ticket_panel_quota_reached",
            "panel_channel_wrong_guild",
        ] {
            assert_eq!(error_code(&anyhow::anyhow!(code)), code);
        }
        assert_eq!(
            error_code(&anyhow::anyhow!("x")),
            "ticket_panel_publish_failed"
        );
    }

    #[tokio::test]
    async fn unconfigured_panel_never_contacts_discord() {
        let store = Store::open(":memory:").unwrap();
        assert_eq!(
            publish(
                &store,
                "token",
                "1",
                &json!({}),
                1,
                "http://127.0.0.1:1",
                false
            )
            .await
            .unwrap(),
            Value::Null
        );
    }

    #[test]
    fn panel_has_working_button_and_cannot_ping() {
        let body = panel_body(&json!({"panelTitle":"Help", "panelDescription":"@everyone"}));
        assert_eq!(body["content"], "**Help**\n@everyone");
        assert_eq!(body["allowed_mentions"]["parse"], json!([]));
        assert_eq!(
            body["components"][0]["components"][0]["custom_id"],
            "ticket:open"
        );
    }
}
