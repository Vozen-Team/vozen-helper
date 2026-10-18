//! Poll banners share the existing navy/mint identity. Native Discord text owns the live deadline.
use super::suggestion_card::{escape, message_lines, rasterize};

pub struct Card<'a> {
    pub id: i64,
    pub question: &'a str,
    pub options: &'a [String],
    pub counts: Option<&'a [i64]>,
    pub end_at: i64,
}

pub(super) fn needs_full_text(question: &str, options: &[String]) -> bool {
    message_lines(question).1
        || options.iter().any(|option| {
            let (lines, truncated) = message_lines(option);
            truncated || lines.len() > 2
        })
        || question
            .chars()
            .chain(options.iter().flat_map(|o| o.chars()))
            .any(|c| c.len_utf16() > 1)
}

fn svg(card: &Card<'_>) -> String {
    let (question, _) = message_lines(card.question);
    let body_top = 120 + 40 * question.len();
    let mut y = body_top;
    let total: u128 = card
        .counts
        .unwrap_or_default()
        .iter()
        .take(card.options.len())
        .map(|n| (*n).max(0) as u128)
        .sum();
    let mut rows = String::new();
    for (index, option) in card.options.iter().take(5).enumerate() {
        let (mut lines, truncated) = message_lines(option);
        let clipped = truncated || lines.len() > 2;
        lines.truncate(2);
        if clipped {
            lines.last_mut().unwrap().push('…');
        }
        let row_height = 34 * lines.len() + if card.counts.is_some() { 48 } else { 28 };
        rows.push_str(&format!(
            r##"<rect x="32" y="{y}" width="736" height="{row_height}" rx="10" fill="#18283A"/>"##
        ));
        rows.push_str(&format!(
            r##"<text x="48" y="{}" fill="#8EE5D2" font-size="24" font-weight="700">{}.</text>"##,
            y + 32,
            index + 1
        ));
        for (line_index, line) in lines.iter().enumerate() {
            rows.push_str(&format!(
                r##"<text x="86" y="{}" fill="#F4F7FB" font-size="24">{}</text>"##,
                y + 32 + 34 * line_index,
                escape(line)
            ));
        }
        if let Some(counts) = card.counts {
            let count = counts.get(index).copied().unwrap_or(0).max(0);
            let percent = (count as u128 * 100).checked_div(total).unwrap_or(0);
            let bar_y = y + row_height - 18;
            rows.push_str(&format!(r##"<text x="748" y="{}" text-anchor="end" fill="#8EE5D2" font-size="20">{count} {} · {percent}%</text><rect x="48" y="{bar_y}" width="704" height="5" rx="2" fill="#294056"/>"##,y+row_height-30,if count == 1 {"vote"}else{"votes"}));
            if percent > 0 {
                rows.push_str(&format!(
                    r##"<rect x="48" y="{bar_y}" width="{}" height="5" rx="2" fill="#8EE5D2"/>"##,
                    704 * count as u128 / total
                ));
            }
        }
        y += row_height + 12;
    }
    let height = y + 62;
    let (state, color) = if card.counts.is_some() {
        ("Closed", "#B7C4FF")
    } else {
        ("Open", "#8EE5D2")
    };
    let footer = if card.counts.is_some() {
        format!("{total} {}", if total == 1 { "vote" } else { "votes" })
    } else {
        chrono::DateTime::from_timestamp_millis(card.end_at)
            .map(|d| format!("Closes {}", d.format("%d %b %Y · %H:%M UTC")))
            .unwrap_or_else(|| "See deadline below".into())
    };
    let question = question.iter().enumerate().map(|(i,line)|format!(r##"<text x="32" y="{}" fill="#F4F7FB" font-size="30" font-weight="700">{}</text>"##,120+40*i,escape(line))).collect::<String>();
    format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" width="800" height="{height}" viewBox="0 0 800 {height}"><rect width="800" height="{height}" rx="20" fill="#101A29"/><g font-family="sans-serif"><text x="32" y="62" fill="#F4F7FB" font-size="34" font-weight="700">Poll #{}</text><rect x="556" y="30" width="212" height="44" rx="12" fill="#223548"/><text x="662" y="60" text-anchor="middle" fill="{color}" font-size="22" font-weight="700">{state}</text>{question}{rows}<path d="M32 {} H768" stroke="#365269"/><text x="32" y="{}" fill="#BACBDD" font-size="18">{}</text><text x="768" y="{}" text-anchor="end" fill="#BACBDD" font-size="18">Vozen Polls</text></g></svg>"##,
        card.id,
        y + 4,
        height - 22,
        escape(&footer),
        height - 22
    )
}

pub fn render(card: &Card<'_>) -> Option<Vec<u8>> {
    rasterize(&svg(card))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_and_closed_poll_banners_are_readable_and_distinct() {
        let options = vec!["30".into(), "31".into()];
        let mut card = Card {
            id: 1,
            question: "Quantos dias tem o mês?",
            options: &options,
            counts: None,
            end_at: 1_792_072_800_000,
        };
        let open = render(&card).expect("open poll image");
        let pixels = resvg::tiny_skia::Pixmap::decode_png(&open).unwrap();
        assert_eq!(pixels.width(), 800);
        assert!(pixels.height() < 1100);
        let ink = (95..180)
            .flat_map(|y| (32..730).map(move |x| (x, y)))
            .filter(|(x, y)| {
                let p = pixels.pixel(*x, *y).unwrap();
                p.red() > 210 && p.green() > 210
            })
            .count();
        assert!(ink > 150, "question must rasterize as real text");
        for text in ["Poll #1", "Open", "Quantos dias", "30", "31", "UTC"] {
            assert!(svg(&card).contains(text));
        }
        card.counts = Some(&[1, 3]);
        let closed = svg(&card);
        for text in ["Closed", "1 vote", "3 votes", "25%", "75%", "4 votes"] {
            assert!(closed.contains(text), "missing {text}");
        }
        assert_ne!(render(&card).unwrap(), open);
        assert!(!closed.contains("Closes"));
        card.counts = Some(&[0, 0]);
        assert!(svg(&card).contains("0 votes"));
        assert!(!svg(&card).contains("NaN"));
    }

    #[test]
    fn poll_text_is_escaped_and_long_labels_keep_a_native_text_fallback() {
        let options = vec![
            "<script>&\"".into(),
            "W".repeat(100),
            "😀".repeat(100),
            "short".into(),
            "last".into(),
        ];
        let card = Card {
            id: 2,
            question: &"long question ".repeat(40),
            options: &options,
            counts: Some(&[1, 1, 0, 0, 0]),
            end_at: i64::MAX,
        };
        assert!(needs_full_text(card.question, card.options));
        let xml = svg(&card);
        assert!(!xml.contains("<script>"));
        assert!(xml.contains("&lt;script&gt;&amp;&quot;"));
        assert!(xml.contains("last"));
        let png = render(&card).unwrap();
        assert!(png.len() < 500_000);
        let pixels = resvg::tiny_skia::Pixmap::decode_png(&png).unwrap();
        assert!(pixels.height() <= 1100);
    }
}
