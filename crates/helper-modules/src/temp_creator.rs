//! One recorded Creator Channel per guild, shared by dashboard and slash setup.
use helper_store::Store;
use reqwest::{Client, RequestBuilder, header};
use serde_json::{Value, json};

static SETUP_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
const SETTING: &str = "utility.temp_channels.creator_channel_id";
const NAME: &str = "➕ Creator Channel";

fn id(value: &Value) -> Option<&str> {
    value
        .as_str()
        .filter(|text| text.parse::<u64>().is_ok_and(|id| id > 0))
}

async fn discord(request: RequestBuilder, uncertain: &'static str) -> Result<Value, &'static str> {
    let response = request
        .header(header::USER_AGENT, "DiscordBot (https://vozen.org, 1.0)")
        .send()
        .await
        .map_err(|_| uncertain)?;
    match response.status().as_u16() {
        200..=299 => response.json().await.map_err(|_| uncertain),
        403 => Err("temp_creator_permissions_required"),
        429 => Err("temp_creator_rate_limited"),
        _ => Err(uncertain),
    }
}

pub async fn setup(
    store: &Store,
    client: &Client,
    base: &str,
    auth: &str,
    guild: &str,
    category: Option<&str>,
) -> Result<Value, &'static str> {
    let _guard = SETUP_LOCK.lock().await;
    let channels = discord(
        client
            .get(format!("{base}/guilds/{guild}/channels"))
            .header(header::AUTHORIZATION, auth),
        "temp_creator_context_unavailable",
    )
    .await?;
    let channels = channels
        .as_array()
        .ok_or("temp_creator_context_unavailable")?;
    if channels
        .iter()
        .any(|channel| channel["guild_id"].as_str().is_some_and(|id| id != guild))
    {
        return Err("temp_creator_context_unavailable");
    }
    let category = category
        .map(|category| {
            channels
                .iter()
                .find(|channel| {
                    channel["id"].as_str() == Some(category) && channel["type"].as_u64() == Some(4)
                })
                .ok_or("temp_creator_category_unavailable")
        })
        .transpose()?;
    let category_id = category
        .map(|category| &category["id"])
        .cloned()
        .unwrap_or(Value::Null);
    let saved = store
        .get_setting(guild, SETTING)
        .map_err(|_| "temp_creator_store_error")?;
    if let Some(channel) = channels
        .iter()
        .find(|channel| channel["id"].as_str() == saved.as_deref() && saved.is_some())
    {
        if channel["type"].as_u64() != Some(2) {
            return Err("temp_creator_record_changed");
        }
        if category.is_none() || channel["parent_id"] == category_id {
            return Ok(channel.clone());
        }
        // Move only our recorded hub; preserve its name and permission overwrites.
        let moved = discord(
            client
                .patch(format!("{base}/channels/{}", saved.as_deref().unwrap()))
                .header(header::AUTHORIZATION, auth)
                .json(&json!({"parent_id":category_id})),
            "temp_creator_move_uncertain",
        )
        .await?;
        if moved["id"] != channel["id"]
            || moved["type"].as_u64() != Some(2)
            || moved["parent_id"] != category_id
            || moved["permission_overwrites"] != channel["permission_overwrites"]
        {
            return Err("temp_creator_move_uncertain");
        }
        return Ok(moved);
    }
    // A previous write with an unknown outcome must not produce a second hub.
    if channels.iter().any(|channel| {
        channel["type"].as_u64() == Some(2)
            && channel["name"].as_str() == Some(NAME)
            && channel["parent_id"] == category_id
    }) {
        return Err("temp_creator_name_exists");
    }
    let permissions = category
        .map(|category| category["permission_overwrites"].clone())
        .unwrap_or_else(|| json!([]));
    if !permissions.is_array() {
        return Err("temp_creator_category_unavailable");
    }
    let payload =
        json!({"name":NAME,"type":2,"parent_id":category_id,"permission_overwrites":permissions});
    let channel = discord(
        client
            .post(format!("{base}/guilds/{guild}/channels"))
            .header(header::AUTHORIZATION, auth)
            .json(&payload),
        "temp_creator_creation_uncertain",
    )
    .await?;
    let channel_id = id(&channel["id"]).ok_or("temp_creator_creation_uncertain")?;
    if channel["type"].as_u64() != Some(2)
        || channel["guild_id"].as_str() != Some(guild)
        || channel["parent_id"] != payload["parent_id"]
        || channel["permission_overwrites"] != permissions
    {
        return Err("temp_creator_creation_uncertain");
    }
    store
        .set_setting(guild, SETTING, channel_id)
        .map_err(|_| "temp_creator_created_not_recorded")?;
    Ok(channel)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn fixture(replies: Vec<(u16, Value)>) -> (String, tokio::task::JoinHandle<Vec<Value>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let mut requests = vec![];
            for (status, body) in replies {
                let (mut socket, _) =
                    tokio::time::timeout(std::time::Duration::from_secs(5), listener.accept())
                        .await
                        .unwrap()
                        .unwrap();
                let mut request = vec![];
                let end = loop {
                    let mut bytes = [0; 4096];
                    let count = socket.read(&mut bytes).await.unwrap();
                    assert!(count > 0);
                    request.extend_from_slice(&bytes[..count]);
                    assert!(request.len() < 100_000);
                    if let Some(end) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
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
                            break end;
                        }
                    }
                };
                let headers = String::from_utf8_lossy(&request[..end]);
                let mut line = headers.lines().next().unwrap().split_whitespace();
                let method = line.next().unwrap();
                let path = line.next().unwrap();
                let payload = if request.len() == end + 4 {
                    Value::Null
                } else {
                    serde_json::from_slice(&request[end + 4..]).unwrap()
                };
                requests.push(json!({"method":method,"path":path,"body":payload}));
                let body = body.to_string();
                socket.write_all(format!("HTTP/1.1 {status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).as_bytes()).await.unwrap();
            }
            requests
        });
        (base, server)
    }

    fn category() -> Value {
        json!({"id":"4","guild_id":"1","type":4,"permission_overwrites":[]})
    }
    fn hub(parent: &str) -> Value {
        json!({"id":"9","guild_id":"1","name":NAME,"type":2,"parent_id":parent,"permission_overwrites":[]})
    }

    #[tokio::test]
    async fn concurrent_dashboard_and_command_setup_create_only_one_permanent_hub() {
        let store = Store::open(":memory:").unwrap();
        let client = Client::new();
        let (base, server) = fixture(vec![
            (200, json!([category()])),
            (200, hub("4")),
            (200, json!([category(), hub("4")])),
        ])
        .await;
        let (first, second) = tokio::join!(
            setup(&store, &client, &base, "Bot fixture", "1", Some("4")),
            setup(&store, &client, &base, "Bot fixture", "1", Some("4"))
        );
        assert_eq!(first.unwrap()["id"], "9");
        assert_eq!(second.unwrap()["id"], "9");
        assert_eq!(
            store.get_setting("1", SETTING).unwrap().as_deref(),
            Some("9")
        );
        assert_eq!(store.active_temp_channels("1").unwrap(), 0);
        let requests = server.await.unwrap();
        assert_eq!(
            requests
                .iter()
                .filter(|request| request["method"] == "POST")
                .count(),
            1
        );
        assert_eq!(
            requests[1]["body"],
            json!({"name":NAME,"type":2,"parent_id":"4","permission_overwrites":[]})
        );
    }

    #[tokio::test]
    async fn recorded_hub_moves_to_the_new_category_without_changing_its_permissions_or_name() {
        let store = Store::open(":memory:").unwrap();
        let client = Client::new();
        store.set_setting("1", SETTING, "9").unwrap();
        let mut old = hub("2");
        old["name"] = json!("Custom creator");
        old["permission_overwrites"] = json!([{"id":"1","type":0,"allow":"0","deny":"1024"}]);
        let mut moved = old.clone();
        moved["parent_id"] = json!("4");
        let (base, server) =
            fixture(vec![(200, json!([category(), old])), (200, moved.clone())]).await;
        assert_eq!(
            setup(&store, &client, &base, "Bot fixture", "1", Some("4"))
                .await
                .unwrap(),
            moved
        );
        let requests = server.await.unwrap();
        assert_eq!(
            requests[1],
            json!({"method":"PATCH","path":"/channels/9","body":{"parent_id":"4"}})
        );
        assert_eq!(
            store.get_setting("1", SETTING).unwrap().as_deref(),
            Some("9")
        );
    }

    #[tokio::test]
    async fn creation_failure_can_retry_without_losing_the_category() {
        let store = Store::open(":memory:").unwrap();
        let client = Client::new();
        store
            .set_setting(
                "1",
                "utility.temp_channels.created_category",
                r#"{"id":"4"}"#,
            )
            .unwrap();
        let (base, server) = fixture(vec![
            (200, json!([category()])),
            (403, json!({"code":50013})),
            (200, json!([category()])),
            (200, hub("4")),
        ])
        .await;
        assert_eq!(
            setup(&store, &client, &base, "Bot fixture", "1", Some("4"))
                .await
                .unwrap_err(),
            "temp_creator_permissions_required"
        );
        assert!(store.get_setting("1", SETTING).unwrap().is_none());
        assert_eq!(
            setup(&store, &client, &base, "Bot fixture", "1", Some("4"))
                .await
                .unwrap()["id"],
            "9"
        );
        assert_eq!(
            store
                .get_setting("1", "utility.temp_channels.created_category")
                .unwrap()
                .as_deref(),
            Some(r#"{"id":"4"}"#)
        );
        assert_eq!(server.await.unwrap().len(), 4);
    }

    #[tokio::test]
    async fn unknown_creation_outcome_does_not_adopt_or_duplicate_an_unrecorded_hub() {
        let store = Store::open(":memory:").unwrap();
        let client = Client::new();
        let (base, server) = fixture(vec![
            (200, json!([category()])),
            (200, json!({"id":"9","type":0})),
            (200, json!([category(), hub("4")])),
        ])
        .await;
        assert_eq!(
            setup(&store, &client, &base, "Bot fixture", "1", Some("4"))
                .await
                .unwrap_err(),
            "temp_creator_creation_uncertain"
        );
        assert_eq!(
            setup(&store, &client, &base, "Bot fixture", "1", Some("4"))
                .await
                .unwrap_err(),
            "temp_creator_name_exists"
        );
        assert!(store.get_setting("1", SETTING).unwrap().is_none());
        assert_eq!(
            server
                .await
                .unwrap()
                .iter()
                .filter(|r| r["method"] == "POST")
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn missing_category_wrong_guild_and_changed_record_never_write_to_discord() {
        for (channels, error) in [
            (json!([]), "temp_creator_category_unavailable"),
            (
                json!([{"id":"4","guild_id":"2","type":4}]),
                "temp_creator_context_unavailable",
            ),
            (
                json!([category(),{"id":"9","guild_id":"1","type":0}]),
                "temp_creator_record_changed",
            ),
        ] {
            let store = Store::open(":memory:").unwrap();
            let client = Client::new();
            store.set_setting("1", SETTING, "9").unwrap();
            let (base, server) = fixture(vec![(200, channels)]).await;
            assert_eq!(
                setup(&store, &client, &base, "Bot fixture", "1", Some("4"))
                    .await
                    .unwrap_err(),
                error
            );
            assert_eq!(server.await.unwrap()[0]["method"], "GET");
            assert_eq!(
                store.get_setting("1", SETTING).unwrap().as_deref(),
                Some("9")
            );
        }
    }
}
