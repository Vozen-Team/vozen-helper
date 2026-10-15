//! One direct banner followed by native vote controls. No Discord writes in tests.
use serde_json::{Value, json};
use serenity::all::{
    ActionRowComponent, ButtonKind, ChannelId, Context, CreateAttachment, Message, MessageId, User,
};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex, OnceLock, Weak},
};

struct Visual {
    png: Vec<u8>,
    alt: String,
}

pub(super) struct Content<'a> {
    pub id: i64,
    pub author: &'a str,
    pub text: &'a str,
    pub status: &'a str,
    pub up: i64,
    pub down: i64,
}

impl Content<'_> {
    fn caption(&self) -> String {
        format!("**Suggestion #{}** by {}", self.id, self.author)
    }
    fn fallback(&self) -> String {
        super::render_suggestion_message(
            self.id,
            self.author,
            self.text,
            self.status,
            self.up,
            self.down,
        )
    }
}

pub(super) fn vote_id(raw: &str) -> Option<i64> {
    let id = raw
        .strip_suffix(":public")
        .or_else(|| raw.strip_suffix(":anonymous"))
        .unwrap_or(raw)
        .parse::<i64>()
        .ok()?;
    (id > 0).then_some(id)
}

pub(super) fn update_lock(id: i64) -> Arc<tokio::sync::Mutex<()>> {
    // Keep database mutation + banner delivery ordered for this suggestion, not
    // across the entire server. Weak references release idle message locks.
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

pub(super) fn published_author(id: i64, author_id: &str, message: &Message) -> String {
    // Serenity 0.12 drops V2 Text Display fields. Preserve the original visibility
    // in the bot-authored button IDs instead of consulting today's anonymous setting.
    let marker = format!("suggest:up:{id}:public");
    let public = message.components.iter().flat_map(|row| &row.components).any(|component|
        matches!(component,ActionRowComponent::Button(button) if matches!(&button.data, ButtonKind::NonLink {custom_id,..} if custom_id == &marker)));
    if public {
        format!("<@{author_id}>")
    } else {
        super::suggestion_author_label(id, author_id, &message.content)
    }
}

fn payload(content: &Content<'_>, visual: Option<&Visual>, against: bool, editing: bool) -> Value {
    let mut components = vec![
        json!({"type":10,"content":if visual.is_some() {content.caption()} else {content.fallback()}}),
    ];
    let mut attachments = vec![];
    if let Some(visual) = visual {
        components.push(json!({"type":12,"items":[{"media":{"url":"attachment://suggestion.png"},"description":visual.alt}]}));
        attachments.push(json!({"id":0,"filename":"suggestion.png","description":visual.alt}));
        if super::suggestion_card::needs_full_text(content.text) {
            components.push(json!({"type":10,"content":content.text}));
        }
    }
    let visibility = if content.author == "Anonymous" {
        "anonymous"
    } else {
        "public"
    };
    let mut buttons = vec![
        json!({"type":2,"style":3,"label":"Support","custom_id":format!("suggest:up:{}:{visibility}",content.id)}),
    ];
    if against {
        buttons.push(json!({"type":2,"style":4,"label":"Against","custom_id":format!("suggest:down:{}:{visibility}",content.id)}));
    }
    components.push(json!({"type":1,"components":buttons}));
    let mut packet = json!({"flags":32768,"components":components,"attachments":attachments,"allowed_mentions":{"parse":[],"users":[],"roles":[],"replied_user":false}});
    if editing {
        packet["content"] = Value::Null;
        packet["embeds"] = json!([]);
    }
    packet
}

async fn deliver(
    ctx: &Context,
    channel: ChannelId,
    existing: Option<MessageId>,
    content: &Content<'_>,
    visual: Option<&Visual>,
    against: bool,
) -> serenity::Result<Message> {
    let files = visual
        .map(|image| {
            CreateAttachment::bytes(image.png.clone(), "suggestion.png").description(&image.alt)
        })
        .into_iter()
        .collect();
    let packet = payload(content, visual, against, existing.is_some());
    if let Some(id) = existing {
        ctx.http.edit_message(channel, id, &packet, files).await
    } else {
        ctx.http.send_message(channel, files, &packet).await
    }
}

fn alt_text(content: &Content<'_>, author: &str) -> String {
    let mut units = 0;
    format!(
        "Suggestion #{} by {author}. {}. Support {}, Against {}. {}",
        content.id, content.status, content.up, content.down, content.text
    )
    .chars()
    .take_while(|c| {
        units += c.len_utf16();
        units <= 1_000
    })
    .collect()
}

pub(super) async fn publish(
    ctx: &Context,
    channel: ChannelId,
    existing: Option<MessageId>,
    content: &Content<'_>,
    user: Option<&User>,
    against: bool,
) -> serenity::Result<Message> {
    // Do not even fetch an avatar for an anonymous publication.
    let user = user.filter(|_| content.author != "Anonymous");
    let author = user
        .map(|user| user.global_name.as_deref().unwrap_or(&user.name))
        .unwrap_or(if content.author == "Anonymous" {
            "Anonymous"
        } else {
            "Member"
        })
        .to_owned();
    let avatar = if let Some(user) = user {
        super::starboard_display::avatar(user).await
    } else {
        None
    };
    let text = content.text.to_owned();
    let status = content.status.to_owned();
    let (id, up, down) = (content.id, content.up, content.down);
    let alt = alt_text(content, &author);
    let visual = tokio::task::spawn_blocking(move || {
        super::suggestion_card::render(&super::suggestion_card::Card {
            id,
            author: &author,
            message: &text,
            status: &status,
            up,
            down,
            avatar: avatar
                .as_ref()
                .map(|(mime, bytes)| (mime.as_str(), bytes.as_slice())),
        })
        .map(|png| Visual { png, alt })
    })
    .await
    .ok()
    .flatten();
    match deliver(ctx, channel, existing, content, visual.as_ref(), against).await {
        Err(error) if visual.is_some() && super::starboard_display::definite_rejection(&error) => {
            tracing::warn!("Suggestion banner rejected; attempting text-only fallback");
            deliver(ctx, channel, existing, content, None, against).await
        }
        result => result,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample<'a>() -> Content<'a> {
        Content {
            id: 7,
            author: "<@99>",
            text: "batata frita",
            status: "pending",
            up: 3,
            down: 1,
        }
    }

    #[test]
    fn vote_and_status_updates_share_a_lock_without_blocking_other_suggestions() {
        let first = update_lock(100);
        let second = update_lock(100);
        let other = update_lock(101);
        assert!(Arc::ptr_eq(&first, &second));
        let held = first.try_lock().unwrap();
        assert!(second.try_lock().is_err());
        assert!(other.try_lock().is_ok());
        drop(held);
        assert!(second.try_lock().is_ok());
    }

    #[test]
    fn legacy_and_banner_vote_ids_are_supported_without_accepting_arbitrary_suffixes() {
        for raw in ["7", "7:public", "7:anonymous"] {
            assert_eq!(vote_id(raw), Some(7));
        }
        for raw in ["0", "-7", "7:other", "7:public:anonymous", "invalid"] {
            assert_eq!(vote_id(raw), None);
        }
    }

    #[test]
    fn long_unicode_alt_text_keeps_status_and_vote_counts_before_the_excerpt() {
        let mut content = sample();
        let text = "😀".repeat(1_000);
        content.text = &text;
        let alt = alt_text(&content, "Rexy");
        assert!(alt.starts_with("Suggestion #7 by Rexy. pending. Support 3, Against 1. "));
        assert!(alt.encode_utf16().count() <= 1_000);
    }

    #[test]
    fn suggestion_gallery_precedes_vote_buttons_and_has_no_nested_embed() {
        let visual = Visual {
            png: vec![1, 2],
            alt: "batata frita".into(),
        };
        for editing in [false, true] {
            let packet = payload(&sample(), Some(&visual), true, editing);
            assert_eq!(packet["flags"], 32768);
            assert!(packet["content"].is_null());
            assert!(
                packet["embeds"]
                    .as_array()
                    .is_none_or(|items| items.is_empty())
            );
            let components = packet["components"].as_array().unwrap();
            assert_eq!(components[0]["content"], "**Suggestion #7** by <@99>");
            assert_eq!(components[1]["type"], 12);
            assert_eq!(
                components[1]["items"][0]["media"]["url"],
                "attachment://suggestion.png"
            );
            let buttons = components.last().unwrap();
            assert_eq!(buttons["type"], 1);
            assert_eq!(buttons["components"][0]["custom_id"], "suggest:up:7:public");
            assert_eq!(
                buttons["components"][1]["custom_id"],
                "suggest:down:7:public"
            );
            assert_eq!(packet["attachments"].as_array().unwrap().len(), 1);
            assert_eq!(packet["allowed_mentions"]["parse"], serde_json::json!([]));
            for component in components {
                serde_json::from_value::<serenity::all::ActionRow>(component.clone())
                    .expect("Serenity decodes V2 response");
            }
        }
    }

    #[test]
    fn suggestion_fallback_keeps_full_text_votes_and_removes_stale_attachment() {
        let content = sample();
        let packet = payload(&content, None, false, true);
        assert_eq!(packet["components"][0]["content"], content.fallback());
        assert!(packet["attachments"].as_array().unwrap().is_empty());
        assert_eq!(
            packet["components"][1]["components"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        let mut long = sample();
        let text = "very long suggestion ".repeat(50);
        long.text = &text;
        let packet = payload(
            &long,
            Some(&Visual {
                png: vec![],
                alt: String::new(),
            }),
            true,
            false,
        );
        assert_eq!(packet["components"][2]["content"], text);
    }

    #[test]
    fn suggestion_anonymity_survives_legacy_and_v2_publications() {
        let mut old = serenity::all::Message::default();
        old.content = "**Suggestion #7** by <@99>\nold text".into();
        assert_eq!(published_author(7, "99", &old), "<@99>");
        let mut modern = old.clone();
        modern.content.clear();
        modern.components =
            serde_json::from_value(payload(&sample(), None, true, true)["components"].clone())
                .unwrap();
        assert_eq!(published_author(7, "99", &modern), "<@99>");
        let mut anonymous = sample();
        anonymous.author = "Anonymous";
        modern.components =
            serde_json::from_value(payload(&anonymous, None, true, true)["components"].clone())
                .unwrap();
        assert_eq!(published_author(7, "99", &modern), "Anonymous");
        modern.components.clear();
        assert_eq!(published_author(7, "99", &modern), "Anonymous");
    }
}
