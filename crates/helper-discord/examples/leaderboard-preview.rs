use helper_discord::leaderboard_card::{Row, render};

fn main() {
    let output = std::env::args().nth(1).expect("PNG output path required");
    let rows = vec![
        Row {
            name: "Member 1".into(),
            xp: 1620,
        },
        Row {
            name: "Member 2".into(),
            xp: 438,
        },
        Row {
            name: "Member 3".into(),
            xp: 250,
        },
    ];
    std::fs::write(output, render(&rows, 0).expect("render leaderboard PNG"))
        .expect("write preview");
}
