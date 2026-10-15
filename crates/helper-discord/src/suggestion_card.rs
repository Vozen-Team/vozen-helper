//! Readable, direct-image Suggestions banners, matching the Starboard palette.
use base64::{Engine, engine::general_purpose::STANDARD};
use std::sync::{Arc, OnceLock};

pub struct Card<'a> {
    pub id: i64,
    pub author: &'a str,
    pub message: &'a str,
    pub status: &'a str,
    pub up: i64,
    pub down: i64,
    pub avatar: Option<(&'a str, &'a [u8])>,
}

fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn glyph_weight(character: char) -> usize {
    match character {
        'i' | 'l' | 'I' | 'j' | '.' | ',' | ':' | ';' | '!' | '\'' | '|' => 35,
        'm' | 'w' | 'M' | 'W' | '@' => 100,
        ' ' => 40,
        c if c.is_ascii_uppercase() => 80,
        c if c.is_ascii() => 65,
        _ => 120,
    }
}

fn message_lines(value: &str) -> (Vec<String>, bool) {
    let mut lines = vec![String::new()];
    let mut width = 0;
    let mut truncated = false;
    'text: for character in value.chars().filter(|c| !c.is_control() || *c == '\n') {
        if character == '\n' {
            if lines.len() == 6 {
                truncated = true;
                break;
            }
            lines.push(String::new());
            width = 0;
            continue;
        }
        while width + glyph_weight(character) > 2_200 {
            if lines.len() == 6 {
                truncated = true;
                break 'text;
            }
            let line = lines.last_mut().unwrap();
            let carry = if let Some(space) = line.rfind(' ').filter(|index| *index > 0) {
                let carry = line.split_off(space + 1);
                line.truncate(space);
                carry
            } else {
                String::new()
            };
            width = carry.chars().map(glyph_weight).sum();
            lines.push(carry);
        }
        if character == ' ' && lines.last().unwrap().is_empty() {
            continue;
        }
        lines.last_mut().unwrap().push(character);
        width += glyph_weight(character);
    }
    if truncated {
        let last = lines.last_mut().unwrap();
        while last.chars().map(glyph_weight).sum::<usize>() > 2_080 {
            last.pop();
        }
        last.push('…');
    }
    (lines, truncated)
}

pub(super) fn needs_full_text(value: &str) -> bool {
    message_lines(value).1
}

fn svg(card: &Card<'_>) -> String {
    let (lines, truncated) = message_lines(card.message);
    let height = 270 + 42 * lines.len().max(2);
    let (status, color) = match card.status {
        "approved" => ("Approved", "#8EE5D2"),
        "denied" => ("Declined", "#FF9BB2"),
        "considered" => ("Under review", "#FFC56B"),
        _ => ("Pending", "#B7C4FF"),
    };
    let author: String = card
        .author
        .chars()
        .filter(|c| !c.is_control())
        .take(45)
        .collect();
    let author = escape(&author);
    let message = lines
        .iter()
        .enumerate()
        .map(|(index, line)| {
            format!(
                r##"<text x="32" y="{}" fill="#F4F7FB" font-size="30">{}</text>"##,
                182 + index * 42,
                escape(line)
            )
        })
        .collect::<String>();
    let avatar = card.avatar.filter(|(mime,bytes)| card.author != "Anonymous" && matches!(*mime,"image/png"|"image/jpeg"|"image/webp") && bytes.len() <= 256*1024)
        .map(|(mime,bytes)| format!(r#"<image href="data:{mime};base64,{}" x="32" y="90" width="36" height="36" clip-path="url(#avatar)" preserveAspectRatio="xMidYMid slice"/>"#,STANDARD.encode(bytes)))
        .unwrap_or_else(|| r##"<circle cx="50" cy="103" r="6" fill="#8EE5D2"/><path d="M39 119 C39 107 61 107 61 119" fill="#8EE5D2"/>"##.into());
    let continuation = if truncated {
        r##"<text x="32" y="32" fill="#BACBDD" font-size="18">Full suggestion below</text>"##
    } else {
        ""
    };
    format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" width="800" height="{height}" viewBox="0 0 800 {height}">
      <defs><clipPath id="avatar"><circle cx="50" cy="108" r="18"/></clipPath><clipPath id="body"><rect x="32" y="148" width="736" height="{}"/></clipPath><clipPath id="author"><rect x="82" y="88" width="686" height="40"/></clipPath></defs>
      <rect width="800" height="{height}" rx="20" fill="#101A29"/>
      <g font-family="sans-serif">
        <text x="32" y="62" fill="#F4F7FB" font-size="34" font-weight="700">Suggestion #{}</text>
        <rect x="556" y="30" width="212" height="44" rx="12" fill="#223548"/>
        <text x="662" y="60" text-anchor="middle" fill="{color}" font-size="22" font-weight="700">{status}</text>
        <circle cx="50" cy="108" r="19" fill="#223548"/>{avatar}
        <text x="82" y="116" fill="#8EE5D2" font-size="22" font-weight="700" clip-path="url(#author)">{author}</text>
        <path d="M32 142 H768" stroke="#365269"/>
        <g clip-path="url(#body)">{message}</g>
        <g transform="translate(0 {})">{continuation}</g>
        <path d="M32 {} H768" stroke="#365269"/>
        <text x="32" y="{}" fill="#8EE5D2" font-size="23" font-weight="700">Support  {}</text>
        <text x="240" y="{}" fill="#FFB3C5" font-size="23" font-weight="700">Against  {}</text>
        <text x="768" y="{}" text-anchor="end" fill="#BACBDD" font-size="18">Vozen Suggestions</text>
      </g></svg>"##,
        height - 254,
        card.id,
        height - 126,
        height - 68,
        height - 28,
        card.up.max(0),
        height - 28,
        card.down.max(0),
        height - 28
    )
}

pub fn render(card: &Card<'_>) -> Option<Vec<u8>> {
    static FONTS: OnceLock<Arc<resvg::usvg::fontdb::Database>> = OnceLock::new();
    let fonts = FONTS.get_or_init(|| {
        let mut fonts = resvg::usvg::fontdb::Database::new();
        fonts.load_system_fonts();
        let family = if fonts
            .faces()
            .any(|face| face.families.iter().any(|(name, _)| name == "DejaVu Sans"))
        {
            "DejaVu Sans"
        } else {
            "Arial"
        };
        fonts.set_sans_serif_family(family);
        Arc::new(fonts)
    });
    fonts.faces().next()?;
    let options = resvg::usvg::Options {
        fontdb: fonts.clone(),
        ..Default::default()
    };
    let tree = resvg::usvg::Tree::from_str(&svg(card), &options).ok()?;
    let mut pixels = resvg::tiny_skia::Pixmap::new(800, tree.size().height() as u32)?;
    resvg::render(
        &tree,
        resvg::tiny_skia::Transform::identity(),
        &mut pixels.as_mut(),
    );
    pixels.encode_png().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample<'a>() -> Card<'a> {
        Card {
            id: 1,
            author: "Rexy",
            message: "batata frita",
            status: "pending",
            up: 2,
            down: 1,
            avatar: None,
        }
    }

    #[test]
    fn suggestion_banner_rasterizes_readable_text_and_status() {
        let png = render(&sample()).expect("render suggestion PNG");
        let pixels = resvg::tiny_skia::Pixmap::decode_png(&png).unwrap();
        assert_eq!(pixels.width(), 800);
        assert!(pixels.height() >= 300 && pixels.height() <= 700);
        assert!(png.len() < 500_000);
        let white = (155..190)
            .flat_map(|y| (32..390).map(move |x| (x, y)))
            .filter(|(x, y)| {
                let p = pixels.pixel(*x, *y).unwrap();
                p.red() > 210 && p.green() > 210 && p.blue() > 210
            })
            .count();
        assert!(white > 80, "message text must actually rasterize");
        let xml = svg(&sample());
        assert!(xml.contains("Suggestion #1"));
        assert!(xml.contains("batata frita"));
        assert!(xml.contains("Pending"));
        assert!(xml.contains("Support  2"));
        assert!(xml.contains("Against  1"));
    }

    #[test]
    fn suggestion_states_votes_and_anonymous_identity_are_rendered() {
        let mut card = sample();
        for (status, label) in [
            ("approved", "Approved"),
            ("denied", "Declined"),
            ("considered", "Under review"),
            ("pending", "Pending"),
        ] {
            card.status = status;
            assert!(svg(&card).contains(label));
        }
        card.author = "Anonymous";
        card.up = 19;
        card.down = -1;
        let xml = svg(&card);
        assert!(xml.contains("Anonymous"));
        assert!(!xml.contains("Rexy"));
        assert!(xml.contains("Support  19"));
        assert!(xml.contains("Against  0"));
    }

    #[test]
    fn suggestion_text_is_bounded_escaped_and_long_copy_is_detected() {
        let mut card = sample();
        card.message = "<script>&\"\nOlá mundo";
        let xml = svg(&card);
        assert!(!xml.contains("<script>"));
        assert!(xml.contains("&lt;script&gt;&amp;&quot;"));
        assert!(xml.contains("Olá mundo"));
        assert!(!needs_full_text(card.message));
        let (wrapped, truncated) = message_lines(&"hello world ".repeat(10));
        assert!(!truncated);
        assert!(wrapped.iter().all(|line| {
            line.split_whitespace()
                .all(|word| matches!(word, "hello" | "world"))
        }));
        for value in ["W".repeat(1_000), "😀".repeat(1_000), "one\n".repeat(300)] {
            let mut card = sample();
            card.message = &value;
            assert!(needs_full_text(&value));
            let (lines, truncated) = message_lines(&value);
            assert!(truncated);
            assert_eq!(lines.len(), 6);
            assert!(lines.last().unwrap().ends_with('…'));
            assert!(
                lines
                    .iter()
                    .all(|line| line.chars().map(glyph_weight).sum::<usize>() <= 2_300)
            );
            assert!(render(&card).is_some());
        }
    }

    #[test]
    fn suggestion_avatar_is_bounded_and_untrusted_mime_is_rejected() {
        let mut avatar = resvg::tiny_skia::Pixmap::new(32, 32).unwrap();
        avatar.fill(resvg::tiny_skia::Color::from_rgba8(220, 40, 80, 255));
        let avatar = avatar.encode_png().unwrap();
        let mut card = sample();
        card.avatar = Some(("image/png", &avatar));
        let png = render(&card).unwrap();
        let pixels = resvg::tiny_skia::Pixmap::decode_png(&png).unwrap();
        let center = pixels.pixel(50, 108).unwrap();
        assert_eq!((center.red(), center.green(), center.blue()), (220, 40, 80));
        card.avatar = Some(("image/svg+xml", &avatar));
        assert!(!svg(&card).contains("data:image/svg+xml"));
        let oversized = vec![0; 256 * 1024 + 1];
        card.avatar = Some(("image/png", &oversized));
        assert!(!svg(&card).contains("data:image/png"));
    }
}
