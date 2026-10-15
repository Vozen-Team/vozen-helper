//! Native Discord attachment delivery. No messages are sent by renderer tests.
use serenity::all::{ChannelId, Context, CreateAttachment, Message, MessageId, User};
use std::{sync::OnceLock, time::Duration};

struct Visual {
    png: Vec<u8>,
    alt: String,
}

pub(super) struct Content {
    pub caption: String,
    pub fallback: String,
    pub footer: String,
}

fn safe_avatar_url(raw: &str) -> Option<reqwest::Url> {
    let mut url = reqwest::Url::parse(raw).ok()?;
    if url.scheme() != "https"
        || url.host_str() != Some("cdn.discordapp.com")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port().is_some()
        || !(url.path().starts_with("/avatars/") || url.path().starts_with("/embed/avatars/"))
    {
        return None;
    }
    url.set_query(Some("size=128"));
    Some(url)
}

pub(super) async fn avatar(user: &User) -> Option<(String, Vec<u8>)> {
    static CLIENT: OnceLock<Option<reqwest::Client>> = OnceLock::new();
    let client = CLIENT
        .get_or_init(|| {
            reqwest::Client::builder()
                .timeout(Duration::from_secs(2))
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .ok()
        })
        .as_ref()?;
    let url = safe_avatar_url(&user.static_face())?;
    let mut response = client.get(url).send().await.ok()?.error_for_status().ok()?;
    let mime = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)?
        .to_str()
        .ok()?
        .split(';')
        .next()?
        .trim()
        .to_string();
    if !matches!(mime.as_str(), "image/png" | "image/jpeg" | "image/webp")
        || response
            .content_length()
            .is_some_and(|length| length > 256 * 1024)
    {
        return None;
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.ok()? {
        if bytes.len() + chunk.len() > 256 * 1024 {
            return None;
        }
        bytes.extend_from_slice(&chunk);
    }
    Some((mime, bytes))
}

fn attachment(visual: &Visual) -> CreateAttachment {
    CreateAttachment::bytes(visual.png.clone(), "starboard.png").description(&visual.alt)
}

fn payload(
    content: &Content,
    author: serenity::all::UserId,
    visual: Option<&Visual>,
    editing: bool,
) -> serde_json::Value {
    use serde_json::json;
    // Serenity 0.12 builders predate V2. Keep its HTTP rate limiter/multipart
    // transport, but supply the documented Discord component payload directly.
    let mut components = vec![
        json!({"type":10,"content":if visual.is_some() {&content.caption} else {&content.fallback}}),
    ];
    let mut attachments = vec![];
    if let Some(visual) = visual {
        components.push(json!({"type":12,"items":[{"media":{"url":"attachment://starboard.png"},"description":visual.alt}]}));
        components.push(json!({"type":10,"content":content.footer}));
        attachments.push(json!({"id":0,"filename":"starboard.png","description":visual.alt}));
    }
    let mut message = json!({"flags":32768,"components":components,"attachments":attachments,
        "allowed_mentions":super::starboard_allowed_mentions(author)});
    if editing {
        // Required when promoting an existing legacy message to Components V2.
        message["content"] = serde_json::Value::Null;
        message["embeds"] = json!([]);
    }
    message
}

async fn deliver(
    ctx: &Context,
    board: ChannelId,
    existing: Option<MessageId>,
    content: &Content,
    author: serenity::all::UserId,
    visual: Option<&Visual>,
) -> serenity::Result<Message> {
    let files = visual.map(attachment).into_iter().collect();
    let packet = payload(content, author, visual, existing.is_some());
    if let Some(id) = existing {
        ctx.http.edit_message(board, id, &packet, files).await
    } else {
        ctx.http.send_message(board, files, &packet).await
    }
}

pub(super) fn definite_rejection(error: &serenity::Error) -> bool {
    // Never retry a possibly accepted send after a timeout or unknown network error.
    matches!(error, serenity::Error::Http(serenity::http::HttpError::UnsuccessfulRequest(response))
        if response.status_code.is_client_error() && response.status_code.as_u16() != 429)
}

fn alt_text(author: &str, message: &str) -> String {
    let mut units = 0;
    format!("{author}: {message}")
        .chars()
        .take_while(|character| {
            units += character.len_utf16();
            units <= 1_000
        })
        .collect()
}

pub(super) async fn publish(
    ctx: &Context,
    board: ChannelId,
    existing: Option<MessageId>,
    original: &Message,
    count: i64,
    _link: &str,
    content: &Content,
) -> serenity::Result<Message> {
    let author = original
        .member
        .as_ref()
        .and_then(|member| member.nick.as_ref())
        .or(original.author.global_name.as_ref())
        .unwrap_or(&original.author.name)
        .clone();
    let channel = original
        .channel_id
        .to_channel(&ctx.http)
        .await
        .ok()
        .and_then(|channel| channel.guild())
        .map(|channel| channel.name)
        .unwrap_or_else(|| original.channel_id.to_string());
    let message = original.content.clone();
    let avatar = avatar(&original.author).await;
    let alt = alt_text(&author, &message);
    let visual = tokio::task::spawn_blocking(move || {
        super::starboard_card::render(&super::starboard_card::Card {
            author: &author,
            message: &message,
            channel: &channel,
            stars: count,
            avatar: avatar
                .as_ref()
                .map(|(mime, bytes)| (mime.as_str(), bytes.as_slice())),
        })
        .map(|png| Visual { png, alt })
    })
    .await
    .ok()
    .flatten();
    // The card carries the excerpt and alt text; retain the full textual fallback.
    let result = deliver(
        ctx,
        board,
        existing,
        content,
        original.author.id,
        visual.as_ref(),
    )
    .await;
    match result {
        Err(error) if visual.is_some() && definite_rejection(&error) => {
            tracing::warn!("Starboard card rejected; attempting text-only fallback");
            // V2 flags cannot be removed on edit; fallback must also use V2.
            deliver(ctx, board, existing, content, original.author.id, None).await
        }
        result => result,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serenity::all::UserId;
    const LINK: &str = "https://discord.com/channels/1/2/3";

    #[test]
    fn unicode_alt_text_fits_discord_limit() {
        let alt = alt_text("Rexy", &"😀".repeat(2_000));
        assert!(alt.encode_utf16().count() <= 1_000);
        assert!(alt.starts_with("Rexy: "));
    }

    #[test]
    fn avatar_urls_are_restricted_to_static_discord_cdn() {
        assert_eq!(
            safe_avatar_url("https://cdn.discordapp.com/avatars/1/a.png?size=4096")
                .unwrap()
                .query(),
            Some("size=128")
        );
        for url in [
            "http://cdn.discordapp.com/avatars/a.png",
            "https://localhost/avatars/a.png",
            "https://cdn.discordapp.com@localhost/avatars/a.png",
            "https://cdn.discordapp.com/attachments/a.png",
            "https://cdn.discordapp.com:444/avatars/a.png",
        ] {
            assert!(safe_avatar_url(url).is_none());
        }
    }

    #[test]
    fn create_and_edit_use_one_direct_image_without_embed_frame() {
        let visual = Visual {
            png: vec![1, 2],
            alt: "Rexy: batata".into(),
        };
        let content = Content {
            caption: "compact caption".into(),
            fallback: "full original text".into(),
            footer: LINK.into(),
        };
        let create = payload(&content, UserId::new(1), Some(&visual), false);
        let edit = payload(&content, UserId::new(1), Some(&visual), true);
        for packet in [create, edit] {
            assert_eq!(packet["flags"], 32768);
            assert!(packet["content"].is_null());
            assert_eq!(packet["components"][0]["content"], "compact caption");
            assert_eq!(packet["components"][1]["type"], 12);
            assert_eq!(
                packet["components"][1]["items"][0]["media"]["url"],
                "attachment://starboard.png"
            );
            assert_eq!(packet["components"][2]["content"], LINK);
            assert_eq!(packet["components"].as_array().unwrap().len(), 3);
            assert_eq!(packet["attachments"].as_array().unwrap().len(), 1);
            assert_eq!(packet["allowed_mentions"]["users"][0], "1");
            assert_eq!(packet["attachments"][0]["description"], "Rexy: batata");
            // The pinned Serenity decoder must accept the new top-level types.
            for component in packet["components"].as_array().unwrap() {
                serde_json::from_value::<serenity::all::ActionRow>(component.clone())
                    .expect("V2 component response remains decodable");
            }
        }
    }

    #[test]
    fn text_fallback_removes_previous_card_without_losing_original_content() {
        let content = Content {
            caption: "compact caption".into(),
            fallback: "@everyone safe text".into(),
            footer: LINK.into(),
        };
        let packet = payload(&content, UserId::new(1), None, true);
        assert_eq!(packet["components"][0]["content"], "@everyone safe text");
        assert_eq!(packet["flags"], 32768);
        for key in ["attachments", "embeds"] {
            assert!(packet[key].as_array().unwrap().is_empty());
        }
        assert!(
            packet["allowed_mentions"]["parse"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn text_only_create_preserves_the_full_fallback() {
        let content = Content {
            caption: "compact caption".into(),
            fallback: "Full original text and source link".into(),
            footer: LINK.into(),
        };
        let packet = payload(&content, UserId::new(1), None, false);
        assert_eq!(packet["components"][0]["content"], content.fallback);
        assert!(packet.get("embeds").is_none());
        assert!(
            packet["allowed_mentions"]["parse"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }
}
