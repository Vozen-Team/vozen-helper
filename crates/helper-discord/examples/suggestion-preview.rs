fn main() {
    let output = std::env::args().nth(1).expect("output PNG path required");
    let text = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "batata frita".into());
    let status = std::env::args().nth(3).unwrap_or_else(|| "pending".into());
    let author = std::env::args().nth(4).unwrap_or_else(|| "Rexy".into());
    let card = helper_discord::suggestion_card::Card {
        id: 1,
        author: &author,
        message: &text,
        status: &status,
        up: 12,
        down: 1,
        avatar: None,
    };
    std::fs::write(
        output,
        helper_discord::suggestion_card::render(&card).expect("PNG"),
    )
    .expect("write preview");
}
