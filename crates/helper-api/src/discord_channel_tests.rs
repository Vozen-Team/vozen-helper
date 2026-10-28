use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

const GUILD: &str = "100000000000000001";
const CHANNEL: &str = "100000000000000002";
const TOKEN: &str = "synthetic-discord-bot-token";

#[tokio::test]
async fn provider_test_delivery_binds_metadata_to_authenticated_guild_before_post() {
    for (status, metadata, allowed) in [
        (
            200,
            serde_json::json!({"id":CHANNEL,"guild_id":GUILD}),
            true,
        ),
        (
            200,
            serde_json::json!({"id":CHANNEL,"guild_id":"100000000000000099"}),
            false,
        ),
        (200, serde_json::json!({"id":CHANNEL}), false),
        (200, serde_json::json!({"id":CHANNEL,"guild_id":42}), false),
        (
            200,
            serde_json::json!({"id":"other","guild_id":GUILD}),
            false,
        ),
        (403, serde_json::json!({"message":"fixture failure"}), false),
        (
            503,
            serde_json::json!({"message":"fixture unavailable"}),
            false,
        ),
    ] {
        let posts = Arc::new(AtomicUsize::new(0));
        let received = Arc::new(std::sync::Mutex::new(None));
        let post_counter = posts.clone();
        let saved = received.clone();
        let mock = Router::new()
            .route(
                "/channels/{channel}",
                get(move || {
                    let metadata = metadata.clone();
                    async move { (StatusCode::from_u16(status).unwrap(), Json(metadata)) }
                }),
            )
            .route(
                "/channels/{channel}/messages",
                post(
                    move |headers: HeaderMap, Json(body): Json<serde_json::Value>| {
                        let posts = post_counter.clone();
                        let saved = saved.clone();
                        async move {
                            assert_eq!(headers[header::AUTHORIZATION], format!("Bot {TOKEN}"));
                            posts.fetch_add(1, Ordering::SeqCst);
                            *saved.lock().unwrap() = Some(body);
                            Json(serde_json::json!({"id":"100000000000000003"}))
                        }
                    },
                ),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            axum::serve(listener, mock).await.unwrap();
        });
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(2))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        let result = discord_send_channel_message_at(
            &client,
            &base,
            TOKEN,
            GUILD,
            CHANNEL,
            "Test @everyone",
        )
        .await;
        assert_eq!(result.is_ok(), allowed);
        assert_eq!(posts.load(Ordering::SeqCst), usize::from(allowed));
        if allowed {
            let body = received.lock().unwrap().clone().unwrap();
            assert_eq!(body["content"], "Test @everyone");
            assert_eq!(body["allowed_mentions"], serde_json::json!({"parse":[]}));
        }
        assert!(
            discord_send_channel_message_at(&client, &base, TOKEN, GUILD, "../invalid", "test")
                .await
                .is_err()
        );
        assert!(
            discord_send_channel_message_at(&client, &base, TOKEN, "invalid", CHANNEL, "test")
                .await
                .is_err()
        );
        assert_eq!(posts.load(Ordering::SeqCst), usize::from(allowed));
        server.abort();
    }
}
