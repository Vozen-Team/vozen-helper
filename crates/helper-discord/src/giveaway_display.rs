//! Direct-image giveaway delivery, retaining native timestamps and existing Join IDs.
use super::giveaway_card::{Card, State};
use helper_store::GiveawayRecord;
use serde_json::{Value, json};
use serenity::all::{ChannelId, CreateAttachment, Message, MessageId};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex, OnceLock, Weak},
};

pub(super) fn update_lock(id: i64) -> Arc<tokio::sync::Mutex<()>> {
    // Keep entry mutation and panel delivery ordered with panel closure.
    type Locks = Mutex<HashMap<i64, Weak<tokio::sync::Mutex<()>>>>;
    static LOCKS: OnceLock<Locks> = OnceLock::new();
    let mut locks = LOCKS
        .get_or_init(Mutex::default)
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    locks.retain(|_, lock| lock.strong_count() > 0);
    if let Some(lock) = locks.get(&id).and_then(Weak::upgrade) {
        return lock;
    }
    let lock = Arc::new(tokio::sync::Mutex::new(()));
    locks.insert(id, Arc::downgrade(&lock));
    lock
}

pub(super) struct EntryUpdate {
    pub joined: Option<bool>,
    pub panel_updated: bool,
}

pub(super) async fn update_entry(
    http: &serenity::http::Http,
    store: &helper_store::Store,
    id: i64,
    user: &str,
) -> anyhow::Result<EntryUpdate> {
    let lock = update_lock(id);
    let _update = lock.lock().await;
    let Some(giveaway) = store.giveaway(id)? else {
        return Ok(EntryUpdate {
            joined: None,
            panel_updated: true,
        });
    };
    let joined = store.toggle_giveaway_entry(id, user)?;
    if joined.is_none() {
        return Ok(EntryUpdate {
            joined,
            panel_updated: true,
        });
    }
    let participants = store.giveaway_participant_count(id)?;
    let channel = giveaway.channel_id.parse::<u64>()?;
    let message = giveaway
        .message_id
        .as_deref()
        .and_then(|raw| raw.parse::<u64>().ok());
    // A failed edit must not re-toggle a saved entry or create another panel.
    let panel_updated = if let Some(message) = message {
        match publish(
            http,
            ChannelId::new(channel),
            Some(MessageId::new(message)),
            &Content {
                giveaway: &giveaway,
                winners: None,
                rerolled: false,
                participants,
            },
            false,
        )
        .await
        {
            Ok(_) => true,
            Err(error) => {
                tracing::warn!(giveaway_id = id, %error, "entry saved but giveaway participant panel could not be refreshed");
                false
            }
        }
    } else {
        false
    };
    Ok(EntryUpdate {
        joined,
        panel_updated,
    })
}

struct Visual {
    png: Vec<u8>,
    alt: String,
}

pub(super) struct Content<'a> {
    pub giveaway: &'a GiveawayRecord,
    pub winners: Option<&'a [String]>,
    pub rerolled: bool,
    pub participants: u64,
}

impl Content<'_> {
    fn state(&self) -> State {
        match self.winners {
            None => State::Open,
            Some([]) => State::Empty,
            Some(_) if self.rerolled => State::Rerolled,
            Some(_) => State::Ended,
        }
    }
    fn count(&self) -> i64 {
        self.winners
            .map(|winners| winners.len() as i64)
            .unwrap_or(self.giveaway.winners)
    }
    fn caption(&self) -> String {
        format!("**Giveaway #{}**", self.giveaway.id)
    }
    fn footer(&self) -> String {
        let result = match self.winners {
            None => {
                let role = self
                    .giveaway
                    .required_role_id
                    .as_ref()
                    .map(|id| format!("\nRequired role: <@&{id}>"))
                    .unwrap_or_default();
                format!(
                    "Ends <t:{}:R> · <t:{}:f>{role}\nClick **Join** to enter or leave.",
                    self.giveaway.end_at / 1_000,
                    self.giveaway.end_at / 1_000
                )
            }
            Some([]) => "Ended without participants.".into(),
            Some(winners) => format!(
                "{}: {}",
                if self.rerolled {
                    "New winner"
                } else {
                    "Winners"
                },
                winners
                    .iter()
                    .map(|id| format!("<@{id}>"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        };
        format!("**Participants:** {}\n{result}", self.participants)
    }
    fn fallback(&self) -> String {
        format!(
            "{}\nPrize: **{}**\n{} {}\n{}",
            self.caption(),
            self.giveaway.prize,
            self.count(),
            if self.count() == 1 {
                "winner"
            } else {
                "winners"
            },
            self.footer()
        )
    }
}

fn payload(
    content: &Content<'_>,
    visual: Option<&Visual>,
    editing: bool,
    notify_winners: bool,
) -> Value {
    let mut components = vec![
        json!({"type":10,"content":if visual.is_some() {content.caption()} else {content.fallback()}}),
    ];
    let mut attachments = vec![];
    if let Some(visual) = visual {
        components.push(json!({"type":12,"items":[{"media":{"url":"attachment://giveaway.png"},"description":visual.alt}]}));
        attachments.push(json!({"id":0,"filename":"giveaway.png","description":visual.alt}));
        if super::suggestion_card::needs_full_text(&content.giveaway.prize) {
            components
                .push(json!({"type":10,"content":format!("Prize: {}",content.giveaway.prize)}));
        }
        components.push(json!({"type":10,"content":content.footer()}));
    }
    if content.winners.is_none() {
        components.push(json!({"type":1,"components":[{"type":2,"style":1,"label":"Join","custom_id":format!("giveaway:join:{}",content.giveaway.id)}]}));
    }
    let mentions = super::giveaway_allowed_mentions(if notify_winners {
        content.winners.unwrap_or_default()
    } else {
        &[]
    });
    let mut packet = json!({"flags":32768,"components":components,"attachments":attachments,"allowed_mentions":mentions});
    if editing {
        packet["content"] = Value::Null;
        packet["embeds"] = json!([]);
    }
    packet
}

async fn deliver(
    http: &serenity::http::Http,
    channel: ChannelId,
    existing: Option<MessageId>,
    content: &Content<'_>,
    visual: Option<&Visual>,
    notify_winners: bool,
) -> serenity::Result<Message> {
    let files = visual
        .map(|image| {
            CreateAttachment::bytes(image.png.clone(), "giveaway.png").description(&image.alt)
        })
        .into_iter()
        .collect();
    let packet = payload(content, visual, existing.is_some(), notify_winners);
    if let Some(id) = existing {
        http.edit_message(channel, id, &packet, files).await
    } else {
        http.send_message(channel, files, &packet).await
    }
}

pub(super) async fn publish(
    http: &serenity::http::Http,
    channel: ChannelId,
    existing: Option<MessageId>,
    content: &Content<'_>,
    notify_winners: bool,
) -> serenity::Result<Message> {
    let (id, prize, winners, end_at, state) = (
        content.giveaway.id,
        content.giveaway.prize.clone(),
        content.count(),
        content.giveaway.end_at,
        content.state(),
    );
    let participants = content.participants;
    let mut units = 0;
    let alt = format!(
        "Giveaway #{id}. {} {participants} participant(s). {winners} winner(s). Prize: {prize}",
        if state == State::Open {
            "Open."
        } else {
            "Closed."
        }
    )
    .chars()
    .take_while(|c| {
        units += c.len_utf16();
        units <= 1_000
    })
    .collect();
    let visual = tokio::task::spawn_blocking(move || {
        super::giveaway_card::render(&Card {
            id,
            prize: &prize,
            winners,
            participants,
            end_at,
            state,
        })
        .map(|png| Visual { png, alt })
    })
    .await
    .ok()
    .flatten();
    match deliver(
        http,
        channel,
        existing,
        content,
        visual.as_ref(),
        notify_winners,
    )
    .await
    {
        Err(error) if visual.is_some() && super::starboard_display::definite_rejection(&error) => {
            tracing::warn!("Giveaway banner rejected; attempting text-only fallback");
            deliver(http, channel, existing, content, None, notify_winners).await
        }
        result => result,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    fn mock_http(
        statuses: Vec<u16>,
    ) -> (serenity::http::Http, std::thread::JoinHandle<Vec<String>>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let mut requests = vec![];
            for status in statuses {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                    .unwrap();
                let mut request = vec![];
                loop {
                    let mut bytes = [0u8; 4096];
                    let read = stream.read(&mut bytes).unwrap();
                    assert!(read > 0, "local request must finish");
                    request.extend_from_slice(&bytes[..read]);
                    assert!(request.len() < 1_000_000, "bounded fixture request");
                    if let Some(end) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
                        let headers = String::from_utf8_lossy(&request[..end]);
                        let length = headers
                            .lines()
                            .find_map(|line| {
                                line.to_ascii_lowercase()
                                    .strip_prefix("content-length:")
                                    .map(|value| value.trim().parse::<usize>().unwrap())
                            })
                            .unwrap();
                        if request.len() >= end + 4 + length {
                            break;
                        }
                    }
                }
                requests.push(String::from_utf8_lossy(&request).into_owned());
                let body = if status == 200 {
                    serde_json::to_string(&Message::default()).unwrap()
                } else {
                    r#"{"code":50013,"message":"Missing permissions (fixture)"}"#.into()
                };
                write!(stream,"HTTP/1.1 {status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).unwrap();
            }
            requests
        });
        (
            serenity::http::HttpBuilder::new("fixture-only")
                .proxy(format!("http://{address}"))
                .ratelimiter_disabled(true)
                .build(),
            server,
        )
    }

    #[tokio::test]
    async fn joining_and_leaving_refresh_the_public_participant_total() {
        let store = helper_store::Store::open(":memory:").unwrap();
        let id = store
            .create_giveaway("10", "20", "Prize", 1, i64::MAX, None, "host")
            .unwrap();
        store.set_giveaway_message(id, "30").unwrap();
        let (http, server) = mock_http(vec![200, 200, 200]);
        for (user, joined) in [("a", true), ("b", true), ("a", false)] {
            let update = update_entry(&http, &store, id, user).await.unwrap();
            assert_eq!(update.joined, Some(joined));
            assert!(update.panel_updated);
        }
        store.end_giveaway(id).unwrap();
        assert_eq!(
            update_entry(&http, &store, id, "late")
                .await
                .unwrap()
                .joined,
            None
        );
        let requests = server.join().unwrap();
        for (request, count) in requests.iter().zip([1, 2, 1]) {
            assert!(request.starts_with("PATCH /api/v10/channels/20/messages/30 "));
            assert!(request.contains(&format!("**Participants:** {count}")));
            assert!(request.contains("giveaway.png"));
            assert!(request.contains(&format!("giveaway:join:{id}")));
        }
        assert_eq!(store.giveaway_participant_count(id).unwrap(), 1);
    }

    #[tokio::test]
    async fn queued_join_then_close_preserve_final_count_without_reopening_the_panel() {
        let store = helper_store::Store::open(":memory:").unwrap();
        let id = store
            .create_giveaway("10", "20", "Prize", 1, i64::MAX, None, "host")
            .unwrap();
        store.set_giveaway_message(id, "30").unwrap();
        let (http, server) = mock_http(vec![200, 200, 200]);
        let lock = update_lock(id);
        let held = lock.lock().await;
        let joining = update_entry(&http, &store, id, "123");
        tokio::pin!(joining);
        tokio::select! {
            biased;
            _ = &mut joining => panic!("entry must wait for the panel lock"),
            _ = std::future::ready(()) => {}
        }
        let closing = super::super::finish_giveaway(&http, &store, "10", id);
        tokio::pin!(closing);
        tokio::select! {
            biased;
            _ = &mut closing => panic!("closure must wait for the panel lock"),
            _ = std::future::ready(()) => {}
        }
        drop(held);
        let (entry, closed) = tokio::join!(joining, closing);
        assert_eq!(entry.unwrap().joined, Some(true));
        assert!(closed.unwrap());
        assert!(store.giveaway(id).unwrap().unwrap().ended);
        assert_eq!(
            update_entry(&http, &store, id, "late")
                .await
                .unwrap()
                .joined,
            None
        );
        let requests = server.join().unwrap();
        assert_eq!(requests.len(), 3);
        assert!(requests[0].starts_with("PATCH "));
        assert!(requests[0].contains("giveaway:join:"));
        assert!(requests[1].starts_with("POST "));
        assert!(requests[2].starts_with("PATCH "));
        for request in &requests[1..] {
            assert!(request.contains("**Participants:** 1"));
            assert!(!request.contains("giveaway:join:"));
        }
    }

    #[tokio::test]
    async fn participant_refresh_failure_does_not_undo_or_toggle_the_entry_twice() {
        let store = helper_store::Store::open(":memory:").unwrap();
        let id = store
            .create_giveaway("10", "20", "Prize", 1, i64::MAX, None, "host")
            .unwrap();
        store.set_giveaway_message(id, "30").unwrap();
        let (http, server) = mock_http(vec![403, 403]);
        let update = update_entry(&http, &store, id, "member").await.unwrap();
        assert_eq!(update.joined, Some(true));
        assert!(!update.panel_updated);
        assert_eq!(store.giveaway_participant_count(id).unwrap(), 1);
        let requests = server.join().unwrap();
        assert_eq!(requests.len(), 2);
        assert!(requests[1].contains("**Participants:** 1"));
    }

    #[test]
    fn join_and_close_updates_share_only_their_giveaway_lock() {
        let first = update_lock(100);
        let same = update_lock(100);
        let other = update_lock(101);
        assert!(std::sync::Arc::ptr_eq(&first, &same));
        let held = first.try_lock().unwrap();
        assert!(same.try_lock().is_err());
        assert!(other.try_lock().is_ok());
        drop(held);
        assert!(same.try_lock().is_ok());
    }

    #[tokio::test]
    async fn giveaway_native_transport_uploads_png_and_closes_original_without_join() {
        let (http, server) = mock_http(vec![200, 200]);
        let giveaway = sample();
        publish(
            &http,
            ChannelId::new(20),
            None,
            &Content {
                giveaway: &giveaway,
                winners: None,
                rerolled: false,
                participants: 0,
            },
            false,
        )
        .await
        .unwrap();
        let winners = vec!["123".into()];
        publish(
            &http,
            ChannelId::new(20),
            Some(MessageId::new(30)),
            &Content {
                giveaway: &giveaway,
                winners: Some(&winners),
                rerolled: false,
                participants: 0,
            },
            false,
        )
        .await
        .unwrap();
        let requests = server.join().unwrap();
        assert!(requests[0].starts_with("POST "));
        assert!(requests[0].contains("giveaway.png"));
        assert!(requests[0].contains("giveaway:join:1"));
        assert!(requests[1].starts_with("PATCH "));
        assert!(requests[1].contains("giveaway.png"));
        assert!(!requests[1].contains("giveaway:join:"));
    }

    #[tokio::test]
    async fn giveaway_rejected_attachment_uses_one_text_only_fallback() {
        let (http, server) = mock_http(vec![403, 200]);
        let giveaway = sample();
        publish(
            &http,
            ChannelId::new(20),
            None,
            &Content {
                giveaway: &giveaway,
                winners: None,
                rerolled: false,
                participants: 0,
            },
            false,
        )
        .await
        .unwrap();
        let requests = server.join().unwrap();
        assert_eq!(requests.len(), 2);
        assert!(requests[0].contains("giveaway.png"));
        assert!(!requests[1].contains("giveaway.png"));
        assert!(requests[1].contains("bitoque"));
        assert!(requests[1].contains("giveaway:join:1"));
    }

    fn sample() -> helper_store::GiveawayRecord {
        helper_store::GiveawayRecord {
            id: 1,
            guild_id: "10".into(),
            channel_id: "20".into(),
            prize: "bitoque".into(),
            winners: 1,
            end_at: 1_792_072_800_000,
            required_role_id: None,
            host_id: "99".into(),
            created_at: 0,
            message_id: Some("30".into()),
            ended: false,
        }
    }

    #[test]
    fn giveaway_banner_precedes_live_countdown_and_native_join_button() {
        let giveaway = sample();
        let content = Content {
            giveaway: &giveaway,
            winners: None,
            rerolled: false,
            participants: 0,
        };
        let visual = Visual {
            png: vec![1, 2],
            alt: "Giveaway #1: bitoque".into(),
        };
        for editing in [false, true] {
            let packet = payload(&content, Some(&visual), editing, false);
            assert_eq!(packet["flags"], 32768);
            let components = packet["components"].as_array().unwrap();
            assert_eq!(components[1]["type"], 12);
            assert_eq!(
                components[1]["items"][0]["media"]["url"],
                "attachment://giveaway.png"
            );
            assert!(
                components[2]["content"]
                    .as_str()
                    .unwrap()
                    .contains("<t:1792072800:R>")
            );
            assert_eq!(
                components.last().unwrap()["components"][0]["custom_id"],
                "giveaway:join:1"
            );
            assert_eq!(packet["allowed_mentions"]["parse"], serde_json::json!([]));
            for component in components {
                serde_json::from_value::<serenity::all::ActionRow>(component.clone())
                    .expect("V2 response decodes");
            }
            if editing {
                assert!(packet["content"].is_null());
                assert!(packet["embeds"].as_array().unwrap().is_empty());
            }
        }
    }

    #[test]
    fn giveaway_results_only_mention_selected_winners_and_never_keep_join() {
        let giveaway = sample();
        let winners = vec!["123".to_string(), "456".to_string()];
        let content = Content {
            giveaway: &giveaway,
            winners: Some(&winners),
            rerolled: false,
            participants: 0,
        };
        let packet = payload(&content, None, false, true);
        assert_eq!(
            packet["allowed_mentions"]["users"],
            serde_json::json!(["123", "456"])
        );
        assert_eq!(packet["allowed_mentions"]["parse"], serde_json::json!([]));
        assert!(!packet.to_string().contains("giveaway:join:"));
        assert!(packet.to_string().contains("<@123>"));
        assert!(packet["attachments"].as_array().unwrap().is_empty());
        assert!(
            payload(&content, None, true, false)["allowed_mentions"]["users"]
                .as_array()
                .unwrap()
                .is_empty(),
            "editing original must not ping winners twice"
        );
    }

    #[test]
    fn giveaway_fallback_and_empty_result_preserve_prize_without_ping_expansion() {
        let mut giveaway = sample();
        giveaway.prize = "@everyone <@&999> ".repeat(10);
        giveaway.required_role_id = Some("888".into());
        let empty = vec![];
        for winners in [None, Some(empty.as_slice())] {
            let content = Content {
                giveaway: &giveaway,
                winners,
                rerolled: false,
                participants: 0,
            };
            let packet = payload(&content, None, true, true);
            assert!(
                packet["components"][0]["content"]
                    .as_str()
                    .unwrap()
                    .contains(&giveaway.prize)
            );
            assert_eq!(packet["allowed_mentions"]["parse"], serde_json::json!([]));
            assert!(
                packet["allowed_mentions"]["roles"]
                    .as_array()
                    .unwrap()
                    .is_empty()
            );
            if winners.is_some() {
                assert!(content.footer().contains("without participants"));
            }
        }
        giveaway.prize = "😀".repeat(200);
        let content = Content {
            giveaway: &giveaway,
            winners: None,
            rerolled: false,
            participants: 0,
        };
        let visual = Visual {
            png: vec![],
            alt: String::new(),
        };
        let packet = payload(&content, Some(&visual), false, false);
        assert_eq!(
            packet["components"][2]["content"],
            format!("Prize: {}", giveaway.prize),
            "long prize remains complete below its banner excerpt"
        );
    }
}
