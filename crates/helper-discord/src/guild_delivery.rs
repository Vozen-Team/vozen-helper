//! Guild-bound delivery for persisted provider subscriptions, including legacy rows.
use anyhow::{Result, bail};
use serenity::{
    all::{Channel, ChannelId},
    http::Http,
};
use std::time::Duration;

pub(super) async fn send(
    http: &Http,
    guild_id: &str,
    channel_id: &str,
    content: String,
) -> Result<()> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    send_at(
        http,
        &client,
        "https://discord.com/api/v10",
        guild_id,
        channel_id,
        content,
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
) -> Result<()> {
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
    ChannelId::new(channel_id).say(http, content).await?;
    Ok(())
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
            send_at(&http, &client, &api_base, "1", "20", "fixture".into())
                .await
                .unwrap();
            assert_eq!(posts.load(Ordering::SeqCst), 1);
            for body in [
                serde_json::json!({"id":"20","guild_id":"9","type":0,"name":"foreign"}),
                serde_json::json!({"id":"20","type":0,"name":"missing guild"}),
                serde_json::json!({"id":"20","type":1,"recipients":[]}),
                serde_json::json!({"id":"other","guild_id":"1","type":0,"name":"malformed"}),
            ] {
                *metadata.lock().unwrap() = body;
                assert!(
                    send_at(&http, &client, &api_base, "1", "20", "blocked".into())
                        .await
                        .is_err()
                );
            }
            for code in [404, 403, 503] {
                status.store(code, Ordering::SeqCst);
                assert!(
                    send_at(&http, &client, &api_base, "1", "20", "blocked".into())
                        .await
                        .is_err()
                );
            }
            assert_eq!(posts.load(Ordering::SeqCst), 1);
            let before = reads.load(Ordering::SeqCst);
            assert!(
                send_at(&http, &client, &api_base, "0", "20", "blocked".into())
                    .await
                    .is_err()
            );
            assert!(
                send_at(&http, &client, &api_base, "1", "0", "blocked".into())
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
