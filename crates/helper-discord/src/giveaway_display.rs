//! Direct-image giveaway delivery, retaining native timestamps and existing Join IDs.
use super::giveaway_card::{Card, State};
use helper_store::GiveawayRecord;
use serde_json::{Value, json};
use serenity::all::{ChannelId, CreateAttachment, Message, MessageId};

struct Visual {
    png: Vec<u8>,
    alt: String,
}

pub(super) struct Content<'a> {
    pub giveaway: &'a GiveawayRecord,
    pub winners: Option<&'a [String]>,
    pub rerolled: bool,
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
        match self.winners {
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
        }
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
    let mut units = 0;
    let alt = format!(
        "Giveaway #{id}. {} {winners} winner(s). Prize: {prize}",
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
