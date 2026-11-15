//! Guild-bound delivery for persisted provider subscriptions, including legacy rows.
use anyhow::{Result, bail};
use serenity::{
    all::{Channel, ChannelId, CreateAllowedMentions, CreateMessage, RoleId},
    http::Http,
};
use std::time::Duration;

pub(super) async fn send(
    http: &Http,
    guild_id: &str,
    channel_id: &str,
    content: String,
    mention: &str,
) -> Result<()> {
    send_at(
        http,
        &delivery_client()?,
        "https://discord.com/api/v10",
        guild_id,
        channel_id,
        content,
        mention,
    )
    .await
}

/// Provider text (titles, descriptions, captions) is third-party controlled, so
/// Discord must never parse mentions from it. Only the single mention the admin
/// configured on the subscription (validated by the API as `@everyone`,
/// `@here` or `<@&role>`) is allowed to ping.
fn alert_allowed_mentions(mention: &str) -> CreateAllowedMentions {
    let allowed = CreateAllowedMentions::new();
    let mention = mention.trim();
    if mention == "@everyone" || mention == "@here" {
        return allowed.everyone(true);
    }
    match mention
        .strip_prefix("<@&")
        .and_then(|rest| rest.strip_suffix('>'))
        .and_then(|id| id.parse::<u64>().ok())
        .filter(|id| *id > 0)
    {
        Some(role) => allowed.roles(vec![RoleId::new(role)]),
        None => allowed,
    }
}

fn delivery_client() -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .redirect(reqwest::redirect::Policy::none())
        .build()?)
}

/// Fresh check that `channel_id` is a guild channel of `guild_id`. Used before
/// any bot post to a channel id that came from stored configuration.
pub(super) async fn require_guild_channel(
    http: &Http,
    guild_id: &str,
    channel_id: &str,
) -> Result<ChannelId> {
    require_guild_channel_at(
        http,
        &delivery_client()?,
        "https://discord.com/api/v10",
        guild_id,
        channel_id,
    )
    .await
}

async fn send_at(
    http: &Http,
    client: &reqwest::Client,
    api_base: &str,
    guild_id: &str,
    channel_id: &str,
    content: String,
    mention: &str,
) -> Result<()> {
    require_guild_channel_at(http, client, api_base, guild_id, channel_id)
        .await?
        .send_message(
            http,
            CreateMessage::new()
                .content(content)
                .allowed_mentions(alert_allowed_mentions(mention)),
        )
        .await?;
    Ok(())
}

async fn require_guild_channel_at(
    http: &Http,
    client: &reqwest::Client,
    api_base: &str,
    guild_id: &str,
    channel_id: &str,
) -> Result<ChannelId> {
    let guild_id = guild_id
        .parse::<u64>()
        .ok()
        .filter(|id| *id > 0)
        .ok_or_else(|| anyhow::anyhow!("invalid_discord_guild_id"))?;
    let channel_id = channel_id
        .parse::<u64>()
        .ok()
        .filter(|id| *id > 0)
        .ok_or_else(|| anyhow::anyhow!("invalid_discord_channel_id"))?;
    // Check raw field presence: Serenity defaults a missing GuildChannel.guild_id.
    let value = client
        .get(format!("{api_base}/channels/{channel_id}"))
        .header(reqwest::header::AUTHORIZATION, http.token())
        .send()
        .await?
        .error_for_status()?
        .json::<serde_json::Value>()
        .await?;
    let id = |key: &str| value[key].as_str().and_then(|id| id.parse::<u64>().ok());
    if id("id") != Some(channel_id) || id("guild_id") != Some(guild_id) {
        bail!("discord_channel_guild_mismatch");
    }
    let Channel::Guild(_) = serde_json::from_value::<Channel>(value)? else {
        bail!("discord_channel_guild_mismatch");
    };
    Ok(ChannelId::new(channel_id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{Read, Write},
        sync::{
            Arc, Mutex,
            atomic::{AtomicBool, AtomicU16, AtomicUsize, Ordering},
        },
    };

    #[test]
    fn alert_mentions_only_allow_the_configured_mention() {
        let json = |mention: &str| serde_json::to_value(alert_allowed_mentions(mention)).unwrap();
        for mention in ["", "<@123>", "<@&0>", "<@&abc>", "@someone"] {
            let value = json(mention);
            assert_eq!(value["parse"], serde_json::json!([]), "{mention}");
            assert!(
                value["roles"].as_array().is_none_or(Vec::is_empty),
                "{mention}"
            );
            assert!(
                value["users"].as_array().is_none_or(Vec::is_empty),
                "{mention}"
            );
        }
        assert_eq!(json("@everyone")["parse"], serde_json::json!(["everyone"]));
        assert_eq!(json("@here")["parse"], serde_json::json!(["everyone"]));
        let role = json("<@&42>");
        assert_eq!(role["parse"], serde_json::json!([]));
        assert_eq!(role["roles"], serde_json::json!(["42"]));
    }

    #[tokio::test]
    async fn fresh_channel_check_blocks_foreign_dm_missing_and_failed_metadata_before_post() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let proxy = format!("http://{}", listener.local_addr().unwrap());
        let metadata = Arc::new(Mutex::new(
            serde_json::json!({"id":"20","guild_id":"1","type":0,"name":"test"}),
        ));
        let status = Arc::new(AtomicU16::new(200));
        let posts = Arc::new(AtomicUsize::new(0));
        let reads = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let state = (
            metadata.clone(),
            status.clone(),
            posts.clone(),
            reads.clone(),
            stop.clone(),
        );
        let server = std::thread::spawn(move || {
            while !state.4.load(Ordering::SeqCst) {
                let Ok((mut stream, _)) = listener.accept() else {
                    std::thread::sleep(Duration::from_millis(1));
                    continue;
                };
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut request = [0; 8192];
                let size = stream.read(&mut request).unwrap();
                let request = String::from_utf8_lossy(&request[..size]);
                let (code, body) = if request.starts_with("GET /api/v10/channels/20 ") {
                    state.3.fetch_add(1, Ordering::SeqCst);
                    (
                        state.1.load(Ordering::SeqCst),
                        state.0.lock().unwrap().clone(),
                    )
                } else if request.starts_with("POST /api/v10/channels/20/messages ") {
                    state.2.fetch_add(1, Ordering::SeqCst);
                    let mut message = serenity::all::Message::default();
                    message.id = serenity::all::MessageId::new(30);
                    message.channel_id = ChannelId::new(20);
                    (200, serde_json::to_value(message).unwrap())
                } else {
                    (500, serde_json::Value::Null)
                };
                let body = body.to_string();
                write!(stream, "HTTP/1.1 {code} Fixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
            }
        });
        let api_base = format!("{proxy}/api/v10");
        let client = reqwest::Client::new();
        let http = serenity::http::HttpBuilder::new("synthetic-token")
            .proxy(proxy)
            .ratelimiter_disabled(true)
            .build();
        let checks = async {
            send_at(&http, &client, &api_base, "1", "20", "fixture".into(), "")
                .await
                .unwrap();
            assert_eq!(posts.load(Ordering::SeqCst), 1);
            assert!(
                require_guild_channel_at(&http, &client, &api_base, "9", "20")
                    .await
                    .is_err()
            );
            assert_eq!(
                require_guild_channel_at(&http, &client, &api_base, "1", "20")
                    .await
                    .unwrap(),
                ChannelId::new(20)
            );
            for body in [
                serde_json::json!({"id":"20","guild_id":"9","type":0,"name":"foreign"}),
                serde_json::json!({"id":"20","type":0,"name":"missing guild"}),
                serde_json::json!({"id":"20","type":1,"recipients":[]}),
                serde_json::json!({"id":"other","guild_id":"1","type":0,"name":"malformed"}),
            ] {
                *metadata.lock().unwrap() = body;
                assert!(
                    send_at(&http, &client, &api_base, "1", "20", "blocked".into(), "")
                        .await
                        .is_err()
                );
            }
            for code in [404, 403, 503] {
                status.store(code, Ordering::SeqCst);
                assert!(
                    send_at(&http, &client, &api_base, "1", "20", "blocked".into(), "")
                        .await
                        .is_err()
                );
            }
            assert_eq!(posts.load(Ordering::SeqCst), 1);
            let before = reads.load(Ordering::SeqCst);
            assert!(
                send_at(&http, &client, &api_base, "0", "20", "blocked".into(), "")
                    .await
                    .is_err()
            );
            assert!(
                send_at(&http, &client, &api_base, "1", "0", "blocked".into(), "")
                    .await
                    .is_err()
            );
            assert_eq!(reads.load(Ordering::SeqCst), before);
        };
        let result = tokio::time::timeout(Duration::from_secs(20), checks).await;
        stop.store(true, Ordering::SeqCst);
        server.join().unwrap();
        result.unwrap();
    }
}
