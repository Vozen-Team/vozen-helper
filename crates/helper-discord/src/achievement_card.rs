use super::suggestion_card::{escape, rasterize};
use base64::{Engine, engine::general_purpose::STANDARD};
use helper_store::AchievementProgress;

pub(super) fn medal_color(tier: usize) -> &'static str {
    match tier {
        1 => "#E1A578",
        2 => "#CCD5E4",
        3 => "#FFD170",
        4 => "#82DBF7",
        _ => "#526278",
    }
}

pub(super) fn medal_icon(id: &str) -> &'static str {
    match id {
        "messages" => "M-15-12H15V7H-4L-13 15V7H-15Z",
        "voice" => "M-16 5V-5A16 16 0 0 1 16-5V5M-16 0H-9V13H-16ZM9 0H16V13H9Z",
        "reactions" => "M-15 0A15 15 0 1 0 15 0A15 15 0 1 0-15 0M-7-4H-5M5-4H7M-7 5Q0 13 7 5",
        "threads_created" => "M-7-16L-11 16M8-16L4 16M-17-6H17M-17 7H17",
        "threads_joined" => "M-15-10H15V13H-15ZM-6-15V-5M6-15V-5M-7 4L-1 10L10-1",
        "boost" => "M2-19L-12 3H0L-3 20L14-4H3Z",
        _ => "M-15-12L-5 0L-15 12M15-12L5 0L15 12",
    }
}

pub fn svg(
    name: &str,
    guild: &str,
    locale: &str,
    avatar: Option<(&str, &[u8])>,
    rows: &[AchievementProgress],
) -> String {
    let score: f64 = rows
        .iter()
        .map(|row| {
            row.unlocked.iter().filter(|v| **v).count() as f64 / row.thresholds.len().max(1) as f64
        })
        .sum();
    let name = escape(
        &name
            .chars()
            .filter(|c| !c.is_control())
            .take(32)
            .collect::<String>(),
    );
    let guild = escape(
        &guild
            .chars()
            .filter(|c| !c.is_control())
            .take(36)
            .collect::<String>(),
    );
    let label = heading(locale);
    let image = avatar.map(|(mime, bytes)| format!(r#"<image href="data:{mime};base64,{}" x="40" y="36" width="92" height="92" clip-path="url(#avatar)"/>"#,STANDARD.encode(bytes))).unwrap_or_default();
    let mut badges = String::new();
    for (index, row) in rows
        .iter()
        .filter(|row| row.unlocked.iter().any(|unlocked| *unlocked))
        .take(7)
        .enumerate()
    {
        let x = 84 + index * 122;
        let tier = row.unlocked.iter().filter(|v| **v).count();
        let color = medal_color(tier);
        let icon = medal_icon(&row.id);
        badges.push_str(&format!(r##"<g transform="translate({x} 244)"><path d="M0-48L42-24V24L0 48L-42 24V-24Z" fill="{color}" fill-opacity=".18" stroke="{color}" stroke-width="3"/><path d="M0-40L35-20V20L0 40L-35 20V-20Z" fill="none" stroke="{color}" opacity=".35"/><path d="{icon}" fill="none" stroke="{color}" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"/></g>"##));
    }
    let total = rows.len();
    let width = (score / total.max(1) as f64 * 576.0).clamp(0.0, 576.0);
    format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" width="900" height="344" viewBox="0 0 900 344"><defs><clipPath id="avatar"><circle cx="86" cy="82" r="46"/></clipPath></defs><rect x="2" y="2" width="896" height="340" rx="22" fill="#101A29" stroke="#8EE5D2" stroke-width="2"/><path d="M450 2L730 342M570 2L850 342" stroke="#192A3B" stroke-width="34" opacity=".45"/><circle cx="86" cy="82" r="48" fill="#263C4B" stroke="#8EE5D2" stroke-width="2"/>{image}<g font-family="sans-serif"><text x="160" y="58" fill="#F4F7FB" font-size="30" font-weight="700">{name}</text><text x="160" y="86" fill="#AAB8CB" font-size="18">{guild}</text><text x="160" y="116" fill="#8EE5D2" font-size="20">{score:.2} / {total}</text><rect x="160" y="135" width="576" height="8" rx="4" fill="#263346"/><rect x="160" y="135" width="{width:.1}" height="8" rx="4" fill="#8EE5D2"/><text x="42" y="176" fill="#AAB8CB" font-size="14">{label}</text>{badges}</g></svg>"##
    )
}

pub(super) async fn image(
    user: &serenity::all::User,
    rows: Vec<AchievementProgress>,
    guild: &str,
    locale: &str,
) -> Option<Vec<u8>> {
    let avatar = super::starboard_display::avatar(user).await;
    let guild = guild.to_owned();
    let locale = locale.to_owned();
    let name = user.global_name.as_deref().unwrap_or(&user.name).to_owned();
    tokio::task::spawn_blocking(move || {
        rasterize(&svg(
            &name,
            &guild,
            &locale,
            avatar
                .as_ref()
                .map(|(mime, bytes)| (mime.as_str(), bytes.as_slice())),
            &rows,
        ))
    })
    .await
    .ok()
    .flatten()
}

fn heading(locale: &str) -> &'static str {
    match locale {
        "pt-BR" | "pt" => "Conquistas",
        "id" => "Pencapaian",
        "da" => "Præstationer",
        "de" => "Erfolge",
        "es-ES" | "es-419" => "Logros",
        "fr" => "Succès",
        "hr" => "Postignuća",
        "it" => "Obiettivi",
        "lt" => "Pasiekimai",
        "hu" => "Eredmények",
        "nl" => "Prestaties",
        "no" => "Prestasjoner",
        "pl" => "Osiągnięcia",
        "ro" => "Realizări",
        "fi" => "Saavutukset",
        "sv-SE" => "Prestationer",
        "vi" => "Thành tích",
        "tr" => "Başarımlar",
        "cs" => "Úspěchy",
        "el" => "Επιτεύγματα",
        "bg" => "Постижения",
        "ru" => "Достижения",
        "uk" => "Досягнення",
        "hi" => "उपलब्धियाँ",
        "th" => "ความสำเร็จ",
        "zh-CN" => "成就",
        "ja" => "実績",
        "zh-TW" => "成就",
        "ko" => "업적",
        "ar" => "الإنجازات",
        _ => "Achievements",
    }
}

pub(super) fn button_labels(locale: &str) -> (&'static str, &'static str) {
    match locale {
        "pt-BR" | "pt" => ("As tuas conquistas", "Lista de conquistas"),
        "id" => ("Pencapaianmu", "Daftar pencapaian"),
        "da" => ("Dine præstationer", "Liste over præstationer"),
        "de" => ("Deine Erfolge", "Erfolgsliste"),
        "es-ES" | "es-419" => ("Tus logros", "Lista de logros"),
        "fr" => ("Tes succès", "Liste des succès"),
        "hr" => ("Tvoja postignuća", "Popis postignuća"),
        "it" => ("I tuoi obiettivi", "Elenco obiettivi"),
        "lt" => ("Tavo pasiekimai", "Pasiekimų sąrašas"),
        "hu" => ("Eredményeid", "Eredmények listája"),
        "nl" => ("Jouw prestaties", "Prestatielijst"),
        "no" => ("Dine prestasjoner", "Prestasjonsliste"),
        "pl" => ("Twoje osiągnięcia", "Lista osiągnięć"),
        "ro" => ("Realizările tale", "Lista realizărilor"),
        "fi" => ("Saavutuksesi", "Saavutuslista"),
        "sv-SE" => ("Dina prestationer", "Prestationslista"),
        "vi" => ("Thành tích của bạn", "Danh sách thành tích"),
        "tr" => ("Başarıların", "Başarı listesi"),
        "cs" => ("Tvé úspěchy", "Seznam úspěchů"),
        "el" => ("Τα επιτεύγματά σου", "Λίστα επιτευγμάτων"),
        "bg" => ("Твоите постижения", "Списък с постижения"),
        "ru" => ("Твои достижения", "Список достижений"),
        "uk" => ("Твої досягнення", "Список досягнень"),
        "hi" => ("आपकी उपलब्धियाँ", "उपलब्धियों की सूची"),
        "th" => ("ความสำเร็จของคุณ", "รายการความสำเร็จ"),
        "zh-CN" => ("你的成就", "成就列表"),
        "ja" => ("あなたの実績", "実績一覧"),
        "zh-TW" => ("你的成就", "成就列表"),
        "ko" => ("내 업적", "업적 목록"),
        _ => ("Your achievements", "Achievements list"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_unlocked_medals_are_shown_with_their_highest_tier_color() {
        let rows: Vec<_> = (0..=4)
            .map(|tier| AchievementProgress {
                id: "messages".into(),
                name: String::new(),
                description: String::new(),
                value: tier,
                thresholds: vec![1, 2, 3, 4],
                unlocked: (1..=4).map(|threshold| threshold <= tier).collect(),
            })
            .collect();
        let empty = svg("Member", "Test server", "en-US", None, &rows[..1]);
        assert!(
            !empty.contains("<g transform="),
            "locked medals stay hidden"
        );
        let source = svg("Member", "Test server", "en-US", None, &rows);
        assert_eq!(source.matches("<g transform=").count(), 4);
        for (index, color) in ["#E1A578", "#CCD5E4", "#FFD170", "#82DBF7"]
            .iter()
            .enumerate()
        {
            let x = 84 + index * 122;
            assert!(source.contains(&format!(r#"translate({x} 244)"#)));
            assert!(source.contains(&format!(r#"stroke="{color}""#)));
        }
        assert!(!source.contains("<text y="), "medals have no tier counters");
        assert!(!source.contains("#526278"));
    }

    #[test]
    fn achievement_card_is_a_readable_png_and_escapes_profile_text() {
        let store = helper_store::Store::open(":memory:").unwrap();
        for i in 0..20 {
            store
                .record_achievement_event("g", "u", "messages", &i.to_string())
                .unwrap();
        }
        let rows = store.achievement_progress("g", "u", 0).unwrap();
        let source = svg("Member <&>", "Server <&>", "en-US", None, &rows);
        assert!(source.contains("Member &lt;&amp;&gt;"));
        assert!(source.contains("Server &lt;&amp;&gt;"));
        assert!(source.contains(">Achievements</text>"));
        assert!(!source.contains("Vozen Helper"));
        assert!(source.contains("0.25 / 7"));
        let avatar = rasterize(r##"<svg xmlns="http://www.w3.org/2000/svg" width="96" height="96"><rect width="96" height="96" fill="#243F52"/><text x="48" y="66" text-anchor="middle" fill="#8EE5D2" font-family="sans-serif" font-size="48">M</text></svg>"##).unwrap();
        let png = rasterize(&svg(
            "Membro de exemplo",
            "Servidor de exemplo",
            "pt-BR",
            Some(("image/png", &avatar)),
            &rows,
        ))
        .unwrap();
        let pixels = resvg::tiny_skia::Pixmap::decode_png(&png).unwrap();
        assert_eq!((pixels.width(), pixels.height()), (900, 344));
        let pixel = pixels.pixels()[(82 * 900 + 62) as usize];
        assert_eq!(
            (pixel.red(), pixel.green(), pixel.blue()),
            (36, 63, 82),
            "avatar must be embedded"
        );
        assert!(
            pixels
                .pixels()
                .iter()
                .filter(|p| p.red() > 200 && p.green() > 200 && p.blue() > 200)
                .count()
                > 100
        );
        if let Ok(path) = std::env::var("HELPER_ACHIEVEMENTS_PREVIEW") {
            std::fs::write(path, png).unwrap();
        }
        for locale in super::super::private_replies::DISCORD_LOCALES {
            let labels = button_labels(locale);
            assert!(!heading(locale).is_empty());
            assert!(!labels.0.is_empty() && labels.0.chars().count() <= 80);
            if !locale.starts_with("en-") {
                assert_ne!(labels.0, "Your achievements");
                assert_ne!(heading(locale), "Achievements");
            }
        }
    }
}
