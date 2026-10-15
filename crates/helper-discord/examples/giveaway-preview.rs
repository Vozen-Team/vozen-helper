use helper_discord::giveaway_card::{Card, State};
fn main() {
    let output = std::env::args().nth(1).expect("PNG output path required");
    let state = match std::env::args().nth(2).as_deref() {
        Some("ended") => State::Ended,
        Some("empty") => State::Empty,
        Some("rerolled") => State::Rerolled,
        _ => State::Open,
    };
    let prize = std::env::args().nth(3).unwrap_or_else(|| "bitoque".into());
    let card = Card {
        id: 1,
        prize: &prize,
        winners: if state == State::Empty { 0 } else { 1 },
        participants: if state == State::Empty { 0 } else { 27 },
        end_at: 1_792_072_800_000,
        state,
    };
    std::fs::write(
        output,
        helper_discord::giveaway_card::render(&card).expect("render giveaway PNG"),
    )
    .expect("write preview");
}
