//! Direct-image poll delivery. Keep IDs, voting rules and scheduled expiry unchanged.
use helper_store::PollRecord;
use serde_json::{Value, json};
use serenity::all::{ChannelId, CreateAttachment, Message, MessageId};

struct Visual {
    png: Vec<u8>,
    alt: String,
}

fn native_text(poll: &PollRecord, counts: Option<&[i64]>) -> String {
    let options = poll
        .options
        .iter()
        .enumerate()
        .map(|(index, option)| match counts {
            Some(counts) => format!(
                "{}. {} — {} votes",
                index + 1,
                option,
                counts.get(index).copied().unwrap_or(0).max(0)
            ),
            None => format!("{}. {}", index + 1, option),
        })
        .collect::<Vec<_>>()
        .join("\n");
    format!("{}\n{options}", poll.question)
}

fn payload(
    poll: &PollRecord,
    counts: Option<&[i64]>,
    visual: Option<&Visual>,
    editing: bool,
) -> Value {
    let mut components = vec![
        json!({"type":10,"content":format!("**Poll #{}{}**",poll.id,if counts.is_some(){" · Closed"}else{""})}),
    ];
    let mut attachments = vec![];
    if let Some(image) = visual {
        components.push(json!({"type":12,"items":[{"media":{"url":"attachment://poll.png"},"description":image.alt}]}));
        attachments.push(json!({"id":0,"filename":"poll.png","description":image.alt}));
    }
    if visual.is_none() || super::poll_card::needs_full_text(&poll.question, &poll.options) {
        components.push(json!({"type":10,"content":native_text(poll,counts)}));
    }
    if counts.is_none() {
        components.push(json!({"type":10,"content":format!("Ends <t:{}:R>\nChoose an option to vote. Vote again to change your choice.",poll.end_at/1000)}));
        let buttons = poll.options.iter().take(5).enumerate().map(|(index,option)|json!({"type":2,"style":2,"custom_id":format!("poll:{}:{index}",poll.id),"label":format!("{}: {}",index+1,super::truncate(option,70))})).collect::<Vec<_>>();
        components.push(json!({"type":1,"components":buttons}));
    }
    let mut packet = json!({"flags":32768,"components":components,"attachments":attachments,"allowed_mentions":{"parse":[]}});
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
    poll: &PollRecord,
    counts: Option<&[i64]>,
    visual: Option<&Visual>,
) -> serenity::Result<Message> {
    let files = visual
        .map(|image| CreateAttachment::bytes(image.png.clone(), "poll.png").description(&image.alt))
        .into_iter()
        .collect();
    let packet = payload(poll, counts, visual, existing.is_some());
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
    poll: &PollRecord,
    counts: Option<&[i64]>,
) -> serenity::Result<Message> {
    let (id, question, options, end_at, totals) = (
        poll.id,
        poll.question.clone(),
        poll.options.clone(),
        poll.end_at,
        counts.map(<[i64]>::to_vec),
    );
    let alt = format!(
        "Poll #{id}. {}. {}",
        if counts.is_some() { "Closed" } else { "Open" },
        native_text(poll, counts)
    )
    .chars()
    .scan(0, |units, c| {
        *units += c.len_utf16();
        Some((*units, c))
    })
    .take_while(|(units, _)| *units <= 1000)
    .map(|(_, c)| c)
    .collect();
    let visual = tokio::task::spawn_blocking(move || {
        super::poll_card::render(&super::poll_card::Card {
            id,
            question: &question,
            options: &options,
            counts: totals.as_deref(),
            end_at,
        })
        .map(|png| Visual { png, alt })
    })
    .await
    .ok()
    .flatten();
    match deliver(http, channel, existing, poll, counts, visual.as_ref()).await {
        Err(error) if visual.is_some() && super::starboard_display::definite_rejection(&error) => {
            tracing::warn!(
                poll_id = id,
                "Poll banner rejected; attempting text-only fallback"
            );
            deliver(http, channel, existing, poll, counts, None).await
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
                    assert!(read > 0);
                    request.extend_from_slice(&bytes[..read]);
                    assert!(request.len() < 1_000_000);
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
                    r#"{"code":50013,"message":"Fixture failure"}"#.into()
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

    #[test]
    fn user_mentions_stay_disabled_and_long_or_emoji_text_stays_available() {
        let store = helper_store::Store::open(":memory:").unwrap();
        let options = ["@everyone".into(), "<@&123> 😀".into()];
        let id = store.create_poll("g", "20", "<@456>", &options, 0).unwrap();
        let poll = store.poll(id).unwrap().unwrap();
        let visual = Visual {
            png: vec![],
            alt: String::new(),
        };
        for counts in [None, Some([1, 2].as_slice())] {
            let packet = payload(&poll, counts, Some(&visual), false);
            assert_eq!(packet["allowed_mentions"]["parse"], json!([]));
            let text = packet["components"]
                .as_array()
                .unwrap()
                .iter()
                .filter_map(|c| c["content"].as_str())
                .collect::<Vec<_>>()
                .join("\n");
            assert!(text.contains("<@456>"));
            assert!(text.contains("<@&123> 😀"));
        }
    }

    #[tokio::test]
    async fn transport_uploads_png_and_closes_the_original_message_with_frozen_votes() {
        let store = helper_store::Store::open(":memory:").unwrap();
        let id = store
            .create_poll("g", "20", "Question", &["30".into(), "31".into()], i64::MAX)
            .unwrap();
        let poll = store.poll(id).unwrap().unwrap();
        let (http, server) = mock_http(vec![200, 200]);
        publish(&http, ChannelId::new(20), None, &poll, None)
            .await
            .unwrap();
        store.set_poll_message(id, "30").unwrap();
        store.vote_poll(id, "123", 1).unwrap();
        assert!(
            super::super::finish_poll(&http, &store, "g", id)
                .await
                .unwrap()
        );
        assert!(store.poll(id).unwrap().unwrap().closed);
        assert!(!store.vote_poll(id, "124", 0).unwrap());
        let requests = server.join().unwrap();
        assert!(requests[0].starts_with("POST /api/v10/channels/20/messages "));
        assert!(requests[0].contains(&format!("poll:{id}:1")));
        assert!(requests[1].starts_with("PATCH /api/v10/channels/20/messages/30 "));
        assert!(!requests[1].contains(&format!("poll:{id}:")));
        for request in requests {
            assert!(request.contains("poll.png"));
            assert!(request.contains("\"flags\":32768"));
        }
    }

    #[tokio::test]
    async fn definite_rejection_falls_back_to_text_but_ambiguous_send_is_not_repeated() {
        let store = helper_store::Store::open(":memory:").unwrap();
        let id = store
            .create_poll("g", "20", "Question", &["30".into(), "31".into()], 0)
            .unwrap();
        let poll = store.poll(id).unwrap().unwrap();
        let (http, server) = mock_http(vec![403, 200]);
        publish(&http, ChannelId::new(20), None, &poll, None)
            .await
            .unwrap();
        let requests = server.join().unwrap();
        assert!(requests[0].contains("poll.png"));
        assert!(!requests[1].contains("poll.png"));
        assert!(requests[1].contains("Question"));
        assert!(requests[1].contains(&format!("poll:{id}:0")));
        let (http, server) = mock_http(vec![408]);
        assert!(
            publish(&http, ChannelId::new(20), None, &poll, None)
                .await
                .is_err()
        );
        assert_eq!(server.join().unwrap().len(), 1);
    }

    #[test]
    fn poll_banner_keeps_vote_ids_and_removes_buttons_and_old_attachments_on_close() {
        let store = helper_store::Store::open(":memory:").unwrap();
        let id = store
            .create_poll("g", "10", "Question", &["30".into(), "31".into()], 0)
            .unwrap();
        let poll = store.poll(id).unwrap().unwrap();
        let visual = Visual {
            png: vec![1],
            alt: "Question. 30 or 31".into(),
        };
        let open = payload(&poll, None, Some(&visual), false);
        assert_eq!(open["flags"], 32768);
        assert_eq!(
            open["components"][1]["items"][0]["media"]["url"],
            "attachment://poll.png"
        );
        assert_eq!(
            open["components"].as_array().unwrap().last().unwrap()["components"][0]["custom_id"],
            format!("poll:{id}:0")
        );
        let closed = payload(&poll, Some(&[1, 3]), Some(&visual), true);
        assert_eq!(closed["attachments"].as_array().unwrap().len(), 1);
        assert!(closed["content"].is_null());
        assert_eq!(closed["embeds"], json!([]));
        assert!(
            !closed["components"]
                .as_array()
                .unwrap()
                .iter()
                .any(|c| c["type"] == 1)
        );
        for packet in [open, closed, payload(&poll, Some(&[0, 0]), None, true)] {
            assert_eq!(packet["allowed_mentions"]["parse"], json!([]));
        }
        let fallback = payload(&poll, Some(&[1, 3]), None, true);
        let text = fallback.to_string();
        assert!(text.contains("Question"));
        assert!(text.contains("3 votes"));
        assert_eq!(fallback["attachments"], json!([]));
    }
}
