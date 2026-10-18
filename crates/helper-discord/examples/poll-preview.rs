use helper_discord::poll_card::{Card, render};
fn main() {
    let output = std::env::args().nth(1).expect("PNG output path required");
    let state = std::env::args().nth(2).unwrap_or_default();
    let options = if state == "long" {
        vec![
            "Uma opção com bastante texto para confirmar a leitura e a quebra de linha.".into();
            5
        ]
    } else {
        vec!["30".into(), "31".into()]
    };
    let counts = [1, 3];
    let card = Card {
        id: 1,
        question: "Quantos dias tem o mês?",
        options: &options,
        counts: (state == "closed").then_some(counts.as_slice()),
        end_at: 1_792_072_800_000,
    };
    std::fs::write(output, render(&card).expect("render poll PNG")).expect("write preview");
}
