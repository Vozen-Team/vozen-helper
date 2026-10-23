//! Direct-image leaderboard pages, using the existing navy/mint card renderer.
use super::suggestion_card::{escape, rasterize};

pub struct Row {
    pub name: String,
    pub xp: i64,
}

fn svg(rows: &[Row], offset: usize) -> String {
    let height = 200 + rows.len().min(10) * 86;
    let mut body = String::new();
    for (index, row) in rows.iter().take(10).enumerate() {
        let rank = offset + index + 1;
        let y = 130 + index * 86;
        let accent = match rank {
            1 => "#FFD170",
            2 => "#CDD8E5",
            3 => "#DEA781",
            _ => "#8EE5D2",
        };
        let mut name = row
            .name
            .chars()
            .filter(|c| !c.is_control())
            .take(24)
            .collect::<String>();
        if row.name.chars().count() > 24 {
            name.push('…');
        }
        body.push_str(&format!(r##"<rect x="32" y="{y}" width="836" height="72" rx="12" fill="#192A3B"/><circle cx="74" cy="{}" r="25" fill="#263C4B"/><text x="74" y="{}" text-anchor="middle" fill="{accent}" font-size="22" font-weight="700">#{rank}</text><text x="118" y="{}" fill="#F4F7FB" font-size="26" font-weight="700" clip-path="url(#name{index})">{}</text><text x="842" y="{}" text-anchor="end" fill="{accent}" font-size="23" font-weight="700">{} XP</text><defs><clipPath id="name{index}"><rect x="118" y="{y}" width="380" height="72"/></clipPath></defs>"##, y+36,y+44,y+45,escape(&name),y+45,row.xp.max(0)));
    }
    format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" width="900" height="{height}" viewBox="0 0 900 {height}"><rect width="900" height="{height}" rx="24" fill="#101A29"/><g font-family="sans-serif"><path d="M39 37 H69 V57 Q69 76 54 76 Q39 76 39 57 Z M39 43 H31 V51 Q31 61 42 61 M69 43 H77 V51 Q77 61 66 61 M54 76 V86 M43 87 H65" fill="none" stroke="#FFD170" stroke-width="4" stroke-linecap="round"/><text x="98" y="70" fill="#F4F7FB" font-size="34" font-weight="700">/leaderboard</text><text x="866" y="68" text-anchor="end" fill="#8EE5D2" font-size="22">XP</text><path d="M32 104 H868" stroke="#365269"/>{body}<text x="32" y="{}" fill="#BACBDD" font-size="17">/leaderboard-privacy</text><text x="868" y="{}" text-anchor="end" fill="#BACBDD" font-size="17">Vozen Helper</text></g></svg>"##,
        height - 24,
        height - 24
    )
}

pub fn render(rows: &[Row], offset: usize) -> Option<Vec<u8>> {
    rasterize(&svg(rows, offset))
}

fn mention_caption(entries: &[helper_core::LeaderboardEntry]) -> String {
    let mentions = entries
        .iter()
        .take(100)
        .enumerate()
        .filter_map(|(index, row)| {
            row.user_id
                .parse::<u64>()
                .ok()
                .filter(|id| *id > 0)
                .map(|id| format!("**#{}** <@{id}>", index + 1))
        })
        .collect::<Vec<_>>();
    mentions
        .chunks(5)
        .map(|row| row.join(" · "))
        .collect::<Vec<_>>()
        .join("\n")
}

fn response(
    pages: Option<Vec<Vec<u8>>>,
    labels: &[String],
    caption: &str,
    fallback: &str,
) -> serenity::all::EditInteractionResponse {
    use serenity::all::{
        CreateAllowedMentions, CreateAttachment, CreateEmbed, EditInteractionResponse,
    };
    let response = EditInteractionResponse::new().allowed_mentions(CreateAllowedMentions::new());
    // A complete 100-member caption can exceed message content's 2000-character limit.
    let response = if caption.chars().count() <= 2000 {
        response.content(caption)
    } else {
        response
            .content("")
            .embed(CreateEmbed::new().colour(0x8EE5D2).description(caption))
    };
    if let Some(pages) = pages {
        pages
            .into_iter()
            .enumerate()
            .fold(response, |response, (index, png)| {
                response.new_attachment(
                    CreateAttachment::bytes(png, format!("leaderboard-{}.png", index + 1))
                        .description(labels[index].chars().take(1000).collect::<String>()),
                )
            })
    } else if fallback.chars().count() <= 2000 {
        response.content(fallback)
    } else {
        response.new_attachment(CreateAttachment::bytes(
            fallback.as_bytes().to_vec(),
            "leaderboard.txt",
        ))
    }
}

pub(super) async fn send(
    ctx: &serenity::all::Context,
    command: &serenity::all::CommandInteraction,
    entries: Vec<helper_core::LeaderboardEntry>,
) -> anyhow::Result<()> {
    let entries = &entries[..entries.len().min(100)];
    let caption = mention_caption(entries);
    let fallback = entries
        .iter()
        .enumerate()
        .map(|(i, row)| format!("{}. <@{}> — {} XP", i + 1, row.user_id, row.xp))
        .collect::<Vec<_>>()
        .join("\n");
    let mut rows = entries
        .iter()
        .map(|row| Row {
            name: row.user_id.clone(),
            xp: row.xp,
        })
        .collect::<Vec<_>>();
    let mut names = tokio::task::JoinSet::new();
    let permits = std::sync::Arc::new(tokio::sync::Semaphore::new(8));
    for (index, row) in entries.iter().enumerate() {
        let Ok(id) = row.user_id.parse::<u64>() else {
            continue;
        };
        let http = ctx.http.clone();
        let permits = permits.clone();
        names.spawn(async move {
            let _permit = permits.acquire_owned().await.ok()?;
            let user = http.get_user(id.into()).await.ok()?;
            Some((index, user.global_name.unwrap_or(user.name)))
        });
    }
    // Bound profile lookups as a group; unknown names retain their existing user ID.
    let _ = tokio::time::timeout(std::time::Duration::from_secs(3), async {
        while let Some(result) = names.join_next().await {
            if let Ok(Some((index, name))) = result {
                rows[index].name = name;
            }
        }
    })
    .await;
    names.abort_all();
    let labels = rows
        .chunks(10)
        .enumerate()
        .map(|(page, rows)| {
            rows.iter()
                .enumerate()
                .map(|(index, row)| {
                    format!("#{} {} — {} XP", page * 10 + index + 1, row.name, row.xp)
                })
                .collect::<Vec<_>>()
                .join("\n")
        })
        .collect::<Vec<_>>();
    let pages = tokio::task::spawn_blocking(move || {
        rows.chunks(10)
            .enumerate()
            .map(|(page, rows)| render(rows, page * 10))
            .collect::<Option<Vec<_>>>()
    })
    .await
    .ok()
    .flatten();
    if pages.is_none() {
        tracing::warn!("leaderboard rendering failed; sending text fallback");
    }
    command
        .edit_response(ctx, response(pages, &labels, &caption, &fallback))
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn card_escapes_names_and_preserves_positions_and_xp() {
        let rows = vec![
            Row {
                name: "Member <&>".into(),
                xp: 1620,
            },
            Row {
                name: "Other".into(),
                xp: 438,
            },
        ];
        let source = svg(&rows, 0);
        assert!(source.contains("Member &lt;&amp;&gt;"));
        assert!(source.contains("1620 XP"));
        assert!(source.contains("438 XP"));
        assert!(source.contains("#1"));
        assert!(source.contains("#2"));
        assert!(svg(&rows, 10).contains("#11"));
    }

    #[test]
    fn card_is_bounded_and_rasterizes_real_text() {
        let rows = (0..100)
            .map(|_| Row {
                name: "M".repeat(1000),
                xp: i64::MAX,
            })
            .collect::<Vec<_>>();
        let source = svg(&rows, 0);
        assert!(!source.contains("#11<"));
        assert!(!source.contains(&"M".repeat(40)));
        let png = render(&rows, 0).expect("PNG card");
        let image = resvg::tiny_skia::Pixmap::decode_png(&png).unwrap();
        assert_eq!(image.width(), 900);
        assert_eq!(image.height(), 1060);
        assert!(
            image
                .pixels()
                .iter()
                .filter(|p| p.red() > 200 && p.green() > 200 && p.blue() > 200)
                .count()
                > 1000
        );
    }

    #[test]
    fn response_is_direct_images_with_alt_text_and_a_complete_safe_fallback() {
        let image = serde_json::to_value(response(
            Some(vec![vec![1], vec![2]]),
            &["#1 Member — 1620 XP".into(), "#11 Other".into()],
            "**#1** <@123> · **#11** <@456>",
            "unused",
        ))
        .unwrap();
        assert_eq!(image["content"], "**#1** <@123> · **#11** <@456>");
        assert!(image.get("embeds").is_none());
        assert_eq!(image["attachments"].as_array().unwrap().len(), 2);
        assert_eq!(image["attachments"][0]["filename"], "leaderboard-1.png");
        assert_eq!(
            image["attachments"][0]["description"],
            "#1 Member — 1620 XP"
        );
        assert_eq!(image["allowed_mentions"]["parse"], serde_json::json!([]));
        let fallback =
            serde_json::to_value(response(None, &[], "**#1** <@123>", "1. <@123> — 1620 XP"))
                .unwrap();
        assert_eq!(fallback["content"], "1. <@123> — 1620 XP");
        let long =
            serde_json::to_value(response(None, &[], "**#1** <@123>", &"a".repeat(2500))).unwrap();
        assert_eq!(long["content"], "**#1** <@123>");
        assert_eq!(long["attachments"][0]["filename"], "leaderboard.txt");
    }

    #[test]
    fn captions_keep_all_100_mentions_within_discord_limits_without_pings() {
        let entries = (0..101)
            .map(|i| helper_core::LeaderboardEntry {
                user_id: (u64::MAX - i).to_string(),
                xp: 1000 - i as i64,
                opted_out: false,
            })
            .collect::<Vec<_>>();
        let caption = mention_caption(&entries);
        assert!(caption.chars().count() > 2000);
        assert!(caption.chars().count() <= 4096);
        assert!(caption.contains(&format!("**#100** <@{}>", u64::MAX - 99)));
        assert!(!caption.contains(&format!("<@{}>", u64::MAX - 100)));
        for png in [Some(vec![vec![1]]), None] {
            let message =
                serde_json::to_value(response(png, &["page".into()], &caption, &"a".repeat(2500)))
                    .unwrap();
            assert_eq!(message["content"], "");
            assert_eq!(message["embeds"][0]["description"], caption);
            assert_eq!(message["allowed_mentions"]["parse"], serde_json::json!([]));
        }
    }

    #[test]
    fn captions_only_include_the_opt_in_ranking_and_numeric_user_ids() {
        let rows = vec![
            helper_core::LeaderboardEntry {
                user_id: "123".into(),
                xp: 2000,
                opted_out: true,
            },
            helper_core::LeaderboardEntry {
                user_id: "456".into(),
                xp: 1000,
                opted_out: false,
            },
            helper_core::LeaderboardEntry {
                user_id: "@everyone".into(),
                xp: 0,
                opted_out: false,
            },
        ];
        let policy = helper_core::leaderboard_policy_from_json(
            &serde_json::json!({"maxEntries":100,"public":false}),
        );
        let ranking = helper_core::evaluate_leaderboard(&policy, rows);
        assert!(!ranking.public);
        assert_eq!(mention_caption(&ranking.entries), "**#1** <@456>");
    }
}
