//! Starboard/Suggestions visual identity; live countdown stays native to Discord.
use super::suggestion_card::{escape, message_lines, rasterize};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum State {
    Open,
    Ended,
    Empty,
    Rerolled,
}

pub struct Card<'a> {
    pub id: i64,
    pub prize: &'a str,
    pub winners: i64,
    pub end_at: i64,
    pub state: State,
}

fn svg(card: &Card<'_>) -> String {
    let (lines, truncated) = message_lines(card.prize);
    let height = 260 + 42 * lines.len().max(2) + if truncated { 20 } else { 0 };
    let (state, color) = match card.state {
        State::Open => ("Open", "#8EE5D2"),
        State::Ended => ("Ended", "#B7C4FF"),
        State::Empty => ("No entries", "#FFC56B"),
        State::Rerolled => ("Redrawn", "#8EE5D2"),
    };
    let count = card.winners.max(0);
    let winners = format!("{count} {}", if count == 1 { "winner" } else { "winners" });
    let deadline = if card.state == State::Open {
        let date = chrono::DateTime::from_timestamp_millis(card.end_at)
            .map(|date| date.format("%d %b %Y · %H:%M UTC").to_string())
            .unwrap_or_else(|| "see deadline below".into());
        format!("Closes {date}")
    } else if card.state == State::Empty {
        "Nobody entered this giveaway".into()
    } else {
        "See the result below".into()
    };
    let body = lines
        .iter()
        .enumerate()
        .map(|(index, line)| {
            format!(
                r##"<text x="32" y="{}" fill="#F4F7FB" font-size="30">{}</text>"##,
                174 + 42 * index,
                escape(line)
            )
        })
        .collect::<String>();
    let continuation = if truncated {
        r##"<text x="32" y="0" fill="#BACBDD" font-size="18">Full prize below</text>"##
    } else {
        ""
    };
    format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" width="800" height="{height}" viewBox="0 0 800 {height}">
      <defs><clipPath id="prize"><rect x="32" y="140" width="736" height="{}"/></clipPath></defs>
      <rect width="800" height="{height}" rx="20" fill="#101A29"/>
      <g font-family="sans-serif">
        <text x="32" y="62" fill="#F4F7FB" font-size="34" font-weight="700">Giveaway #{}</text>
        <rect x="556" y="30" width="212" height="44" rx="12" fill="#223548"/>
        <text x="662" y="60" text-anchor="middle" fill="{color}" font-size="22" font-weight="700">{state}</text>
        <g stroke="#8EE5D2" stroke-width="3" fill="none" stroke-linejoin="round"><rect x="34" y="106" width="34" height="27" rx="3"/><path d="M32 106 H70 V97 H32 Z M51 97 V133 M51 97 C29 98 32 79 43 86 Z M51 97 C73 98 70 79 59 86 Z"/></g>
        <text x="88" y="124" fill="#8EE5D2" font-size="22" font-weight="700">Prize</text>
        <g clip-path="url(#prize)">{body}</g>
        <g transform="translate(0 {})">{continuation}</g>
        <path d="M32 {} H768" stroke="#365269"/>
        <text x="32" y="{}" fill="#8EE5D2" font-size="24" font-weight="700">{winners}</text>
        <text x="32" y="{}" fill="#BACBDD" font-size="18">{}</text>
        <text x="768" y="{}" text-anchor="end" fill="#BACBDD" font-size="18">Vozen Giveaways</text>
      </g></svg>"##,
        height - 248,
        card.id,
        height - 112,
        height - 92,
        height - 53,
        height - 22,
        escape(&deadline),
        height - 22
    )
}

pub fn render(card: &Card<'_>) -> Option<Vec<u8>> {
    rasterize(&svg(card))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample<'a>() -> Card<'a> {
        Card {
            id: 1,
            prize: "bitoque",
            winners: 1,
            end_at: 1_792_072_800_000,
            state: State::Open,
        }
    }

    #[test]
    fn giveaway_card_has_real_readable_prize_pixels() {
        let png = render(&sample()).expect("giveaway PNG");
        assert!(png.len() < 500_000);
        let image = resvg::tiny_skia::Pixmap::decode_png(&png).unwrap();
        assert_eq!(image.width(), 800);
        assert!((300..=600).contains(&image.height()));
        let text = (140..180)
            .flat_map(|y| (32..380).map(move |x| (x, y)))
            .filter(|(x, y)| {
                let pixel = image.pixel(*x, *y).unwrap();
                pixel.red() > 210 && pixel.green() > 210 && pixel.blue() > 210
            })
            .count();
        assert!(text > 80, "prize text must rasterize, not merely parse");
        let xml = svg(&sample());
        for expected in ["Giveaway #1", "bitoque", "Open", "1 winner", "UTC"] {
            assert!(xml.contains(expected), "missing {expected}");
        }
        assert!(
            !xml.contains("minutes"),
            "countdown belongs in native Discord text"
        );
    }

    #[test]
    fn giveaway_closed_empty_and_reroll_states_are_distinct() {
        let mut card = sample();
        let initial = render(&card).unwrap();
        for (state, label) in [
            (State::Ended, "Ended"),
            (State::Empty, "No entries"),
            (State::Rerolled, "Redrawn"),
        ] {
            card.state = state;
            let xml = svg(&card);
            assert!(xml.contains(label));
            assert!(!xml.contains("Closes "));
            assert_ne!(render(&card).unwrap(), initial);
        }
        card.winners = 2;
        assert!(svg(&card).contains("2 winners"));
    }

    #[test]
    fn giveaway_prizes_are_escaped_and_bounded_without_losing_full_text_contract() {
        let mut card = sample();
        card.prize = "<script>&\" prémio";
        assert!(!svg(&card).contains("<script>"));
        assert!(svg(&card).contains("&lt;script&gt;&amp;&quot;"));
        for text in ["😀".repeat(200), "W".repeat(200), "ola\n".repeat(100)] {
            let mut card = sample();
            card.prize = &text;
            let image = resvg::tiny_skia::Pixmap::decode_png(&render(&card).unwrap()).unwrap();
            assert!(image.height() <= 600);
            assert!(super::super::suggestion_card::needs_full_text(&text));
        }
        card.end_at = i64::MAX;
        assert!(render(&card).is_some());
    }
}
