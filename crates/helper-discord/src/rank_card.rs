use base64::{Engine, engine::general_purpose::STANDARD};
use helper_contracts::RankCardConfig;

const WIDTH: u32 = 900;
const HEIGHT: u32 = 300;

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn safe_hex<'a>(value: &'a str, fallback: &'a str) -> &'a str {
    if value.len() == 7
        && value.starts_with('#')
        && value.as_bytes()[1..].iter().all(u8::is_ascii_hexdigit)
    {
        value
    } else {
        fallback
    }
}

fn font_family(font: &str) -> &'static str {
    match font {
        "inter" => "Inter, Arial, sans-serif",
        "roboto" => "Roboto, Arial, sans-serif",
        "poppins" => "Poppins, Arial, sans-serif",
        "space_grotesk" => "'Space Grotesk', Arial, sans-serif",
        "lexend" => "Lexend, Arial, sans-serif",
        _ => "sans-serif",
    }
}

fn progress_width(xp: i64) -> f32 {
    (xp.rem_euclid(100) as f32 / 100.0) * 560.0
}

pub fn preset_png(preset: &str) -> Option<&'static [u8]> {
    let bytes: &[u8] = match preset {
        "aurora-lake" => {
            include_bytes!("../../../assets/rank-card-banners/banner-01-aurora-lake.png")
        }
        "neon-rain" => include_bytes!("../../../assets/rank-card-banners/banner-02-neon-rain.png"),
        "enchanted-forest" => {
            include_bytes!("../../../assets/rank-card-banners/banner-03-enchanted-forest.png")
        }
        "desert-ruins" => {
            include_bytes!("../../../assets/rank-card-banners/banner-04-desert-ruins.png")
        }
        "coral-cavern" => {
            include_bytes!("../../../assets/rank-card-banners/banner-05-coral-cavern.png")
        }
        "sky-islands" => {
            include_bytes!("../../../assets/rank-card-banners/banner-06-sky-islands.png")
        }
        "volcanic-forge" => {
            include_bytes!("../../../assets/rank-card-banners/banner-07-volcanic-forge.png")
        }
        "moonlit-village" => {
            include_bytes!("../../../assets/rank-card-banners/banner-08-moonlit-village.png")
        }
        "starship-hangar" => {
            include_bytes!("../../../assets/rank-card-banners/banner-09-starship-hangar.png")
        }
        "lavender-storm" => {
            include_bytes!("../../../assets/rank-card-banners/banner-10-lavender-storm.png")
        }
        "crystal-cavern" => {
            include_bytes!("../../../assets/rank-card-banners/banner-11-crystal-cavern.png")
        }
        "sakura-shrine" => {
            include_bytes!("../../../assets/rank-card-banners/banner-12-sakura-shrine.png")
        }
        "cosmic-nebula" => {
            include_bytes!("../../../assets/rank-card-banners/banner-13-cosmic-nebula.png")
        }
        "frost-citadel" => {
            include_bytes!("../../../assets/rank-card-banners/banner-14-frost-citadel.png")
        }
        "tropical-lagoon" => {
            include_bytes!("../../../assets/rank-card-banners/banner-15-tropical-lagoon.png")
        }
        "clockwork-library" => {
            include_bytes!("../../../assets/rank-card-banners/banner-16-clockwork-library.png")
        }
        _ => return None,
    };
    Some(bytes)
}

fn preset_data_uri(preset: &str) -> Option<String> {
    preset_png(preset).map(|bytes| format!("data:image/png;base64,{}", STANDARD.encode(bytes)))
}

/// Produces a self-contained SVG so Discord can display the rank card without
/// a native canvas dependency. Curated banner presets are embedded directly;
/// profile URLs are XML-escaped here.
pub fn render_rank_card(
    config: &RankCardConfig,
    username: &str,
    avatar_url: Option<&str>,
    rank: Option<u64>,
    level: i64,
    xp: i64,
) -> String {
    let background = safe_hex(&config.background_color, "#101725");
    let primary = safe_hex(&config.primary_color, "#8EE5D2");
    let text = safe_hex(&config.text_color, "#F4F7FB");
    let ring = safe_hex(&config.avatar_ring_color, primary);
    let opacity = config.overlay_opacity.clamp(0.0, 0.85);
    let ring_width = config.avatar_ring_width.min(8);
    let username = xml_escape(username);
    let rank_text = rank.map_or_else(|| "—".to_string(), |value| format!("#{value}"));
    let bg_source = config
        .background_preset
        .as_deref()
        .and_then(preset_data_uri);
    let bg_image = bg_source
        .as_deref()
        .map(xml_escape)
        .map(|url| {
            format!(
                r#"<image href="{url}" x="0" y="0" width="{WIDTH}" height="{HEIGHT}" preserveAspectRatio="xMidYMid slice"/>"#
            )
        })
        .unwrap_or_default();
    let avatar_image = avatar_url
        .map(xml_escape)
        .map(|url| {
            format!(
                r#"<image href="{url}" x="58" y="58" width="184" height="184" preserveAspectRatio="xMidYMid slice" clip-path="url(#avatar-clip)"/>"#
            )
        })
        .unwrap_or_default();
    let width = progress_width(xp).max(8.0);
    let xp_current = xp.rem_euclid(100);
    let font = font_family(&config.font);

    format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" width="{WIDTH}" height="{HEIGHT}" viewBox="0 0 {WIDTH} {HEIGHT}">
  <defs>
    <linearGradient id="panel" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="{primary}" stop-opacity=".18"/><stop offset="1" stop-color="{background}" stop-opacity=".96"/></linearGradient>
    <clipPath id="avatar-clip"><circle cx="150" cy="150" r="92"/></clipPath>
  </defs>
  <rect width="{WIDTH}" height="{HEIGHT}" rx="22" fill="{background}"/>
  {bg_image}
  <rect width="{WIDTH}" height="{HEIGHT}" rx="22" fill="#000000" opacity="{opacity:.3}"/>
  <rect width="{WIDTH}" height="{HEIGHT}" rx="22" fill="url(#panel)"/>
  <circle cx="150" cy="150" r="96" fill="none" stroke="{ring}" stroke-width="{ring_width}"/>
  <circle cx="150" cy="150" r="92" fill="#202A3A"/>
  {avatar_image}
  <text x="285" y="72" fill="{text}" font-family="{font}" font-size="30" font-weight="800">{username}</text>
  <text x="285" y="108" fill="{primary}" font-family="{font}" font-size="16" font-weight="700">Rank {rank_text}</text>
  <text x="746" y="108" fill="{text}" font-family="{font}" font-size="16" font-weight="700" text-anchor="end">Level {level}</text>
  <text x="285" y="163" fill="#AAB8CB" font-family="{font}" font-size="15">{xp_current} / 100 XP</text>
  <rect x="285" y="181" width="560" height="18" rx="9" fill="#263346"/>
  <rect x="285" y="181" width="{width:.1}" height="18" rx="9" fill="{primary}"/>
  <text x="285" y="240" fill="#8D9DB4" font-family="{font}" font-size="13">Keep participating to reach the next level.</text>
  <text x="845" y="240" fill="{text}" font-family="{font}" font-size="13" text-anchor="end">{xp} total XP</text>
</svg>"##,
    )
}

pub fn parse_config(raw: Option<String>) -> RankCardConfig {
    raw.and_then(|value| serde_json::from_str(&value).ok())
        .unwrap_or_default()
}

pub fn config_for_plan(raw: Option<String>, premium: bool) -> RankCardConfig {
    if premium {
        parse_config(raw)
    } else {
        RankCardConfig::default()
    }
}

pub fn render_png(
    config: &RankCardConfig,
    username: &str,
    avatar: Option<(&str, &[u8])>,
    rank: Option<u64>,
    level: i64,
    xp: i64,
) -> Option<Vec<u8>> {
    let avatar = avatar
        .filter(|(mime, bytes)| {
            matches!(*mime, "image/png" | "image/jpeg" | "image/webp") && bytes.len() <= 256 * 1024
        })
        .map(|(mime, bytes)| format!("data:{mime};base64,{}", STANDARD.encode(bytes)));
    super::suggestion_card::rasterize(&render_rank_card(
        config,
        username,
        avatar.as_deref(),
        rank,
        level,
        xp,
    ))
}

pub async fn image(
    config: RankCardConfig,
    user: &serenity::all::User,
    rank: Option<u64>,
    level: i64,
    xp: i64,
) -> Option<Vec<u8>> {
    let avatar = super::starboard_display::avatar(user).await;
    let name = user.global_name.as_deref().unwrap_or(&user.name).to_owned();
    tokio::task::spawn_blocking(move || {
        render_png(
            &config,
            &name,
            avatar
                .as_ref()
                .map(|(mime, bytes)| (mime.as_str(), bytes.as_slice())),
            rank,
            level,
            xp,
        )
    })
    .await
    .ok()
    .flatten()
}

pub fn level_up_message(
    png: Option<Vec<u8>>,
    text: &str,
    member: serenity::all::UserId,
) -> serenity::all::CreateMessage {
    use serenity::all::{CreateAllowedMentions, CreateAttachment, CreateMessage};
    let message = CreateMessage::new()
        .content(text)
        .allowed_mentions(CreateAllowedMentions::new().users([member]));
    match png {
        Some(bytes) => message.add_file(
            CreateAttachment::bytes(bytes, "level-up-banner.png")
                .description(text.chars().take(1000).collect::<String>()),
        ),
        None => message,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn level_up_keeps_the_message_above_the_card_without_an_embed() {
        let card = serde_json::to_value(level_up_message(
            Some(vec![1, 2, 3]),
            "Member reached level 15!",
            serenity::all::UserId::new(42),
        ))
        .unwrap();
        assert_eq!(card["content"], "Member reached level 15!");
        assert!(
            card.get("embeds")
                .is_none_or(|value| value.as_array().is_some_and(Vec::is_empty))
        );
        assert_eq!(card["attachments"][0]["filename"], "level-up-banner.png");
        let fallback = serde_json::to_value(level_up_message(
            None,
            "Member reached level 15!",
            serenity::all::UserId::new(42),
        ))
        .unwrap();
        assert_eq!(fallback["content"], "Member reached level 15!");
        assert!(
            fallback
                .get("embeds")
                .is_none_or(|value| value.as_array().is_some_and(Vec::is_empty))
        );
        assert_eq!(
            fallback["allowed_mentions"]["users"],
            serde_json::json!(["42"])
        );
    }

    #[test]
    fn default_banner_is_a_readable_png_without_a_premium_background() {
        let mut avatar = resvg::tiny_skia::Pixmap::new(32, 32).unwrap();
        avatar.fill(resvg::tiny_skia::Color::from_rgba8(220, 40, 80, 255));
        let bytes = avatar.encode_png().unwrap();
        let png = render_png(
            &RankCardConfig::default(),
            "Member & friend",
            Some(("image/png", &bytes)),
            Some(2),
            14,
            1311,
        )
        .unwrap();
        let pixels = resvg::tiny_skia::Pixmap::decode_png(&png).unwrap();
        assert_eq!((pixels.width(), pixels.height()), (900, 300));
        let pixel = |x: usize, y: usize| &pixels.data()[(y * 900 + x) * 4..(y * 900 + x + 1) * 4];
        assert_eq!(
            pixel(150, 150),
            &[220, 40, 80, 255],
            "avatar must be embedded in the PNG"
        );
        let text_pixels = (40..75)
            .flat_map(|y| (285..700).map(move |x| (x, y)))
            .filter(|&(x, y)| {
                let color = pixel(x, y);
                color[0] > 200 && color[1] > 200 && color[2] > 200
            })
            .count();
        assert!(
            text_pixels > 100,
            "member name must rasterize, not merely exist in SVG"
        );
        if let Ok(path) = std::env::var("HELPER_LEVEL_CARD_PREVIEW") {
            std::fs::write(path, &png).unwrap();
        }
    }

    #[test]
    fn premium_background_still_renders_as_a_complete_card() {
        let config = RankCardConfig {
            background_preset: Some("aurora-lake".into()),
            ..Default::default()
        };
        let default =
            render_png(&RankCardConfig::default(), "Member", None, None, 14, 1311).unwrap();
        let premium = render_png(&config, "Member", None, None, 14, 1311).unwrap();
        assert_ne!(default, premium);
        assert!(
            render_png(
                &config,
                "Member",
                Some(("image/svg+xml", b"untrusted")),
                None,
                14,
                1311
            )
            .is_some()
        );
    }

    #[test]
    fn free_card_ignores_saved_premium_customization() {
        let saved = Some(
            serde_json::to_string(&RankCardConfig {
                background_preset: Some("neon-rain".into()),
                primary_color: "#FF0000".into(),
                ..Default::default()
            })
            .unwrap(),
        );
        let free = config_for_plan(saved.clone(), false);
        assert_eq!(free.primary_color, RankCardConfig::default().primary_color);
        assert!(free.background_preset.is_none());
        assert!(free.background_url.is_none());
        let custom = RankCardConfig {
            background_preset: Some("neon-rain".into()),
            ..Default::default()
        };
        assert_eq!(
            config_for_plan(Some(serde_json::to_string(&custom).unwrap()), true).background_preset,
            custom.background_preset
        );
    }

    #[test]
    fn renders_escaped_user_data_and_configured_colours() {
        let config = RankCardConfig {
            primary_color: "#123ABC".into(),
            ..RankCardConfig::default()
        };
        let svg = render_rank_card(
            &config,
            "A & <user>",
            Some("https://cdn.test/avatar.png?a=1&b=2"),
            Some(4),
            12,
            429,
        );
        assert!(svg.contains("A &amp; &lt;user&gt;"));
        assert!(svg.contains("#123ABC"));
        assert!(svg.contains("a=1&amp;b=2"));
        assert!(svg.contains("width=\"162"));
    }

    #[test]
    fn renders_only_curated_background_presets() {
        assert_eq!(helper_contracts::RANK_CARD_BACKGROUND_PRESETS.len(), 16);
        for (id, _) in helper_contracts::RANK_CARD_BACKGROUND_PRESETS {
            let png = preset_png(id).expect("every curated preset has an embedded image");
            assert!(png.starts_with(b"\x89PNG\r\n\x1a\n"));
            let config = RankCardConfig {
                background_preset: Some((*id).into()),
                ..RankCardConfig::default()
            };
            assert!(
                render_rank_card(&config, "member", None, None, 1, 25)
                    .contains("data:image/png;base64,")
            );
            let rendered = render_png(&config, "member", None, None, 1, 25)
                .expect("every curated preset rasterizes");
            assert!(rendered.starts_with(b"\x89PNG\r\n\x1a\n"));
        }
        let config = RankCardConfig {
            background_preset: Some("aurora-lake".into()),
            background_url: Some("https://untrusted.example/image.png".into()),
            ..RankCardConfig::default()
        };
        let svg = render_rank_card(&config, "member", None, None, 1, 25);
        assert!(svg.contains("data:image/png;base64,"));
        assert!(!svg.contains("untrusted.example"));
    }
}
