//! Local, complete-message translations for private interaction feedback.
//! Slots are captured before rendering, never translated or replaced in place.
use std::{
    collections::{BTreeMap, HashMap},
    future::Future,
    sync::OnceLock,
};

pub(super) const DISCORD_LOCALES: &[&str] = &[
    "id", "da", "de", "en-GB", "en-US", "es-ES", "es-419", "fr", "hr", "it", "lt", "hu", "nl",
    "no", "pl", "pt-BR", "ro", "fi", "sv-SE", "vi", "tr", "cs", "el", "bg", "ru", "uk", "hi", "th",
    "zh-CN", "ja", "zh-TW", "ko",
];

tokio::task_local! { static PRIVATE_LOCALE:Option<String>; }

pub(super) async fn with_locale<F: Future>(locale: Option<String>, future: F) -> F::Output {
    PRIVATE_LOCALE.scope(locale, future).await
}

pub(super) fn current_text(input: &str) -> String {
    PRIVATE_LOCALE
        .try_with(|locale| locale.as_deref().map(|locale| text(locale, input)))
        .ok()
        .flatten()
        .unwrap_or_else(|| super::english_bot_text(input))
}

pub(super) fn for_visibility(private: bool, locale: &str, input: &str) -> String {
    if private {
        text(locale, input)
    } else {
        super::english_bot_text(input)
    }
}

#[derive(Clone, Debug)]
enum Part {
    Literal(String),
    Slot(usize),
}

fn parts(template: &str) -> Vec<Part> {
    let mut result = vec![];
    let mut literal = String::new();
    let mut chars = template.chars().peekable();
    while let Some(c) = chars.next() {
        if (c == '{' || c == '}') && chars.peek() == Some(&c) {
            literal.push(c);
            chars.next();
            continue;
        }
        if c == '{' {
            let mut name = String::new();
            while chars.peek().is_some_and(|c| *c != '}') {
                name.push(chars.next().unwrap());
            }
            if chars.peek() == Some(&'}') {
                chars.next();
                if let Ok(index) = name.parse::<usize>() {
                    if !literal.is_empty() {
                        result.push(Part::Literal(std::mem::take(&mut literal)));
                    }
                    result.push(Part::Slot(index));
                    continue;
                }
                literal.push('{');
                literal.push_str(&name);
                literal.push('}');
                continue;
            }
            literal.push('{');
            literal.push_str(&name);
            continue;
        }
        literal.push(c);
    }
    if !literal.is_empty() {
        result.push(Part::Literal(literal));
    }
    result
}

fn slots(template: &str) -> BTreeMap<usize, usize> {
    let mut slots = BTreeMap::new();
    for part in parts(template) {
        if let Part::Slot(index) = part {
            *slots.entry(index).or_default() += 1;
        }
    }
    slots
}

fn render(template: &str, values: &BTreeMap<usize, String>) -> String {
    parts(template)
        .into_iter()
        .map(|part| match part {
            Part::Literal(s) => s,
            Part::Slot(index) => values
                .get(&index)
                .cloned()
                .unwrap_or_else(|| format!("{{{index}}}")),
        })
        .collect()
}

struct Pattern {
    parts: Vec<Part>,
    score: usize,
}
impl Pattern {
    fn new(template: &str) -> Self {
        let parts = parts(template);
        let score = parts
            .iter()
            .map(|part| match part {
                Part::Literal(s) => s.len(),
                Part::Slot(_) => 0,
            })
            .sum();
        Self { parts, score }
    }

    fn capture(&self, input: &str) -> Option<BTreeMap<usize, String>> {
        fn walk(
            parts: &[Part],
            input: &str,
            at: usize,
            values: &mut BTreeMap<usize, String>,
            budget: &mut usize,
        ) -> bool {
            if *budget == 0 {
                return false;
            }
            *budget -= 1;
            let Some((part, rest)) = parts.split_first() else {
                return at == input.len();
            };
            match part {
                Part::Literal(literal) => {
                    input[at..].starts_with(literal)
                        && walk(rest, input, at + literal.len(), values, budget)
                }
                Part::Slot(index) => {
                    if let Some(value) = values.get(index) {
                        let length = value.len();
                        return input[at..].starts_with(value)
                            && walk(rest, input, at + length, values, budget);
                    }
                    let mut ends: Vec<usize> = match rest.first() {
                        None => vec![input.len()],
                        Some(Part::Literal(literal)) => input[at..]
                            .match_indices(literal)
                            .map(|(offset, _)| at + offset)
                            .collect(),
                        Some(Part::Slot(_)) => input[at..]
                            .char_indices()
                            .map(|(offset, _)| at + offset)
                            .chain(std::iter::once(input.len()))
                            .collect(),
                    };
                    // Space-separated IDs/amounts precede a translated status or
                    // configured currency. Keep that numeric field separate even
                    // when the following value itself contains spaces.
                    if matches!(rest.first(),Some(Part::Literal(literal)) if literal == " ")
                        && matches!(rest.get(1), Some(Part::Slot(_)))
                        && let Some(end) = ends.first().copied()
                        && input[at..end].parse::<i64>().is_ok()
                    {
                        ends.truncate(1);
                    }
                    for end in ends.into_iter().rev() {
                        values.insert(*index, input[at..end].to_owned());
                        if walk(rest, input, end, values, budget) {
                            return true;
                        }
                        values.remove(index);
                    }
                    false
                }
            }
        }
        let mut values = BTreeMap::new();
        walk(&self.parts, input, 0, &mut values, &mut 512).then_some(values)
    }
}

struct Catalogue {
    sources: BTreeMap<String, String>,
    languages: HashMap<&'static str, BTreeMap<String, String>>,
    words: HashMap<&'static str, BTreeMap<String, String>>,
    exact: HashMap<String, String>,
    patterns: Vec<(String, Pattern)>,
}

fn catalogue() -> &'static Catalogue {
    static DATA: OnceLock<Catalogue> = OnceLock::new();
    DATA.get_or_init(|| {
        let mut sources: BTreeMap<String, String> =
            serde_json::from_str(include_str!("private-replies/source.json"))
                .expect("checked source catalogue");
        sources.extend(
            serde_json::from_str::<BTreeMap<String, String>>(include_str!(
                "private-replies/extra-source.json"
            ))
            .expect("checked supplemental source catalogue"),
        );
        macro_rules! language {
            ($locale:literal) => {{
                let mut messages = serde_json::from_str::<BTreeMap<String, String>>(include_str!(
                    concat!("private-replies/", $locale, ".json")
                ))
                .expect(concat!("checked catalogue ", $locale));
                messages.extend(
                    serde_json::from_str::<BTreeMap<String, String>>(include_str!(concat!(
                        "private-replies/",
                        $locale,
                        ".extra.json"
                    )))
                    .expect(concat!("checked supplemental catalogue ", $locale)),
                );
                ($locale, messages)
            }};
            ($locale:literal,$suffix:literal) => {
                (
                    $locale,
                    serde_json::from_str::<BTreeMap<String, String>>(include_str!(concat!(
                        "private-replies/",
                        $locale,
                        $suffix,
                        ".json"
                    )))
                    .expect(concat!("checked catalogue ", $locale)),
                )
            };
        }
        let languages = HashMap::from([
            language!("id"),
            language!("da"),
            language!("de"),
            language!("en-GB"),
            language!("en-US"),
            language!("es-ES"),
            language!("es-419"),
            language!("fr"),
            language!("hr"),
            language!("it"),
            language!("lt"),
            language!("hu"),
            language!("nl"),
            language!("no"),
            language!("pl"),
            language!("pt-BR"),
            language!("ro"),
            language!("fi"),
            language!("sv-SE"),
            language!("vi"),
            language!("tr"),
            language!("cs"),
            language!("el"),
            language!("bg"),
            language!("ru"),
            language!("uk"),
            language!("hi"),
            language!("th"),
            language!("zh-CN"),
            language!("ja"),
            language!("zh-TW"),
            language!("ko"),
        ]);
        let words = HashMap::from([
            language!("id", ".words"),
            language!("da", ".words"),
            language!("de", ".words"),
            language!("en-GB", ".words"),
            language!("en-US", ".words"),
            language!("es-ES", ".words"),
            language!("es-419", ".words"),
            language!("fr", ".words"),
            language!("hr", ".words"),
            language!("it", ".words"),
            language!("lt", ".words"),
            language!("hu", ".words"),
            language!("nl", ".words"),
            language!("no", ".words"),
            language!("pl", ".words"),
            language!("pt-BR", ".words"),
            language!("ro", ".words"),
            language!("fi", ".words"),
            language!("sv-SE", ".words"),
            language!("vi", ".words"),
            language!("tr", ".words"),
            language!("cs", ".words"),
            language!("el", ".words"),
            language!("bg", ".words"),
            language!("ru", ".words"),
            language!("uk", ".words"),
            language!("hi", ".words"),
            language!("th", ".words"),
            language!("zh-CN", ".words"),
            language!("ja", ".words"),
            language!("zh-TW", ".words"),
            language!("ko", ".words"),
        ]);
        let mut exact = HashMap::new();
        let mut patterns = vec![];
        for (id, source) in &sources {
            let pattern = Pattern::new(source);
            if slots(source).is_empty() {
                exact.insert(render(source, &BTreeMap::new()), id.clone());
            } else if pattern.score >= 9 {
                patterns.push((id.clone(), pattern));
            }
        }
        patterns.sort_by(|(a, first), (b, second)| {
            second.score.cmp(&first.score).then_with(|| a.cmp(b))
        });
        Catalogue {
            sources,
            languages,
            words,
            exact,
            patterns,
        }
    })
}

fn locale_key(locale: &str) -> &'static str {
    DISCORD_LOCALES
        .iter()
        .find(|key| key.eq_ignore_ascii_case(locale))
        .copied()
        .unwrap_or(match locale {
            "pt" | "pt-PT" => "pt-BR",
            "en" => "en-US",
            "es" => "es-ES",
            "zh" => "zh-TW",
            _ => "en-US",
        })
}

pub(super) fn system_word(input: &str) -> String {
    PRIVATE_LOCALE
        .try_with(|locale| {
            locale
                .as_deref()
                .and_then(|locale| catalogue().words[locale_key(locale)].get(input).cloned())
        })
        .ok()
        .flatten()
        .unwrap_or_else(|| input.to_owned())
}

pub(super) fn text(locale: &str, input: &str) -> String {
    let data = catalogue();
    let locale = locale_key(locale);
    let translated = &data.languages[locale];
    debug_assert_eq!(data.sources.len(), translated.len());
    if let Some(id) = data.exact.get(input) {
        return render(&translated[id], &BTreeMap::new());
    }
    if input.len() <= 12_000 {
        for (id, pattern) in &data.patterns {
            if let Some(mut values) = pattern.capture(input) {
                // This evaluator slot contains an internal privacy operation,
                // unlike tag names, reasons and other user-authored slots.
                if data.sources[id] == "Member {0} is disabled by this server's privacy policy."
                    && let Some(operation) = values.get_mut(&0)
                    && matches!(operation.as_str(), "exports" | "erasure")
                {
                    *operation = data.words[locale][operation.as_str()].clone();
                }
                return render(&translated[id], &values);
            }
        }
    }
    // Unknown/user-authored text is not a phrase-replacement target.
    input.to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn poll_feedback_uses_the_personal_discord_locale_without_partial_replacements() {
        let original = "Voto registado; podes votar novamente para alterar.";
        let en = text("en-US", original);
        assert!(en.contains("vote") || en.contains("Vote"));
        assert!(!en.contains("podes") && !en.contains("Voto"));
        let pt = text("pt-BR", original);
        assert!(pt.contains("Voto") || pt.contains("voto"));
        assert!(!pt.contains("recorded") && !pt.contains("again"));
        assert_eq!(text("en-GB", original), en);
        assert_eq!(text("invalid-locale", original), en);
        let id = catalogue()
            .sources
            .iter()
            .find(|(_, source)| source.as_str() == original)
            .unwrap()
            .0;
        assert_eq!(text("fr", original), catalogue().languages["fr"][id]);
    }

    #[test]
    fn every_discord_locale_has_every_source_key_and_the_same_placeholders() {
        let data = catalogue();
        assert_eq!(DISCORD_LOCALES.len(), 32);
        for locale in DISCORD_LOCALES {
            let translated = &data.languages[*locale];
            assert_eq!(translated.len(), data.sources.len(), "{locale}");
            assert_eq!(data.words[*locale].len(), 18);
            for key in [
                "complete",
                "pending",
                "none",
                "enabled",
                "disabled",
                "reacts",
                "replies",
                "disabled immediately",
                "registered",
                "checked_in",
                "credits",
                "exports",
                "erasure",
                "invalid_reaction",
                "unsupported_action",
                "First steps",
                "Regular",
                "Community pillar",
            ] {
                assert!(!data.words[*locale][key].is_empty());
            }
            for (id, source) in &data.sources {
                let target = translated.get(id).expect("missing translation");
                assert!(!target.trim().is_empty(), "{locale} {id}");
                assert_eq!(slots(source), slots(target), "{locale} {id}");
            }
        }
    }

    #[test]
    fn dynamic_values_and_literal_braces_remain_verbatim_even_when_they_look_like_replies() {
        let pattern = Pattern::new("Tag `{0}` saved.");
        let name = "Voto registado; podes votar novamente para alterar. {1}";
        let input = format!("Tag `{name}` saved.");
        let values = pattern.capture(&input).unwrap();
        assert_eq!(values[&0], name);
        assert_eq!(
            render("Enregistré : {0}", &values),
            format!("Enregistré : {name}")
        );
        assert!(pattern.capture("Prefix Tag `name` saved.").is_none());
        assert!(pattern.capture("Tag `name` saved. Extra").is_none());
        assert_eq!(
            render("{{literal}} {0}", &values),
            format!("{{literal}} {name}")
        );
        assert_eq!(
            text("fr", "custom servidor phrase"),
            "custom servidor phrase"
        );
    }

    #[test]
    fn privacy_policy_feedback_translates_internal_operations_not_arbitrary_slot_values() {
        let data = catalogue();
        let id = data
            .sources
            .iter()
            .find(|(_, source)| {
                source.as_str() == "Member {0} is disabled by this server's privacy policy."
            })
            .unwrap()
            .0;
        for locale in DISCORD_LOCALES {
            for operation in ["exports", "erasure"] {
                assert_eq!(
                    text(
                        locale,
                        &format!("Member {operation} is disabled by this server's privacy policy.")
                    ),
                    render(
                        &data.languages[*locale][id],
                        &BTreeMap::from([(0, data.words[*locale][operation].clone())])
                    )
                );
            }
        }
    }

    #[test]
    fn space_separated_numeric_fields_do_not_consume_multiword_values() {
        for (source, input, expected) in [
            (
                "Workflow #{0} {1}.",
                "Workflow #12 desativado imediatamente.",
                BTreeMap::from([(0, "12".into()), (1, "desativado imediatamente".into())]),
            ),
            (
                "The `{0}` action may append {1} {2} to the ledger.",
                "The `daily` action may append 12 moon coins to the ledger.",
                BTreeMap::from([
                    (0, "daily".into()),
                    (1, "12".into()),
                    (2, "moon coins".into()),
                ]),
            ),
        ] {
            assert_eq!(Pattern::new(source).capture(input).unwrap(), expected);
        }
    }

    #[test]
    fn every_catalogued_template_renders_its_values_without_translating_them() {
        let data = catalogue();
        let values: BTreeMap<usize, String> = (0..20)
            .map(|index| (index, format!("UserValue{index}🔥{{9}}")))
            .collect();
        for (id, source) in &data.sources {
            let pattern = Pattern::new(source);
            let input = render(source, &values);
            if pattern.score < 9 || slots(source).is_empty() {
                continue;
            }
            let captured = pattern
                .capture(&input)
                .unwrap_or_else(|| panic!("failed source pattern {id}: {source}"));
            for index in slots(source).keys() {
                assert_eq!(captured[index], values[index], "{id}");
            }
            for locale in DISCORD_LOCALES {
                let output = render(&data.languages[*locale][id], &captured);
                assert_eq!(text(locale, &input), output, "routing {locale} {id}");
                for index in slots(source).keys() {
                    assert!(output.contains(&values[index]), "{locale} {id}");
                }
            }
        }
    }

    #[test]
    fn components_use_the_actor_locale_not_the_guild_and_user_data_bypasses_translation() {
        use serenity::all::{ComponentInteraction, Message, User};
        let mut component:ComponentInteraction=serde_json::from_value(serde_json::json!({
            "id":"1","application_id":"2","data":{"custom_id":"poll:1:0","component_type":2},
            "guild_id":"10","channel_id":"20","token":"fixture-only","version":1,
            "message":Message::default(),"user":User::default(),"locale":"fr","guild_locale":"pt-BR",
            "entitlements":[],"attachment_size_limit":1000000
        })).unwrap();
        let source = "Voto registado; podes votar novamente para alterar.";
        for locale in DISCORD_LOCALES {
            component.locale = locale.to_string();
            let reply =
                serde_json::to_value(super::super::component_feedback(&component, source)).unwrap();
            assert_eq!(reply["content"], text(locale, source));
            assert_eq!(reply["allowed_mentions"]["parse"], serde_json::json!([]));
        }
        let authored = "Vote recorded.\nVoto registado.\n<@123> {0}";
        let raw = serde_json::to_value(super::super::raw_feedback(authored)).unwrap();
        assert_eq!(raw["content"], authored);
        assert_eq!(raw["allowed_mentions"]["parse"], serde_json::json!([]));
    }

    #[tokio::test]
    async fn concurrent_private_replies_do_not_share_a_guild_or_global_language() {
        let source = "Voto registado; podes votar novamente para alterar.";
        let (en, pt) = tokio::join!(
            with_locale(Some("en-US".into()), async {
                tokio::task::yield_now().await;
                current_text(source)
            }),
            with_locale(Some("pt-BR".into()), async {
                tokio::task::yield_now().await;
                current_text(source)
            })
        );
        assert_eq!(en, text("en-US", source));
        assert_eq!(pt, text("pt-BR", source));
        assert_ne!(en, pt);
        assert_eq!(
            with_locale(None, async { current_text("Role assigned.") }).await,
            "Role assigned."
        );
    }

    #[tokio::test]
    async fn command_visibility_and_personal_locale_do_not_change_with_server_language() {
        use serenity::all::{CommandInteraction, User};
        let store = helper_store::Store::open(":memory:").unwrap();
        store.set_setting("10", "core.language", "fr").unwrap();
        let mut command:CommandInteraction=serde_json::from_value(serde_json::json!({
            "id":"1","application_id":"2","data":{"id":"3","name":"help","type":1,"options":[]},
            "guild_id":"10","channel_id":"20","token":"fixture-only","version":1,
            "user":User::default(),"locale":"ja","guild_locale":"pt-BR","entitlements":[],"attachment_size_limit":1000000
        })).unwrap();
        let content = "This command can only be used in a server.";
        for name in [
            "help",
            "poll",
            "suggest",
            "giveaway-start",
            "privacy",
            "tag",
            "reason",
            "workflow-create",
            "ticket-setup",
            "verify-panel",
        ] {
            command.data.name = name.into();
            let private = super::super::command_response_ephemeral(&store, &command);
            assert!(private, "{name}");
            let reply = with_locale(private.then(|| command.locale.clone()), async {
                current_text(content)
            })
            .await;
            assert_eq!(reply, text("ja", content));
            assert_ne!(reply, text("pt-BR", content));
        }
        for name in ["ping", "rank", "leaderboard"] {
            command.data.name = name.into();
            assert!(
                !super::super::command_response_ephemeral(&store, &command),
                "{name}"
            );
        }
        store
            .set_setting("10", "community.leaderboard.public", "false")
            .unwrap();
        command.data.name = "leaderboard".into();
        assert!(super::super::command_response_ephemeral(&store, &command));
        for locale in DISCORD_LOCALES {
            assert_eq!(
                for_visibility(true, locale, "Unable to complete this action."),
                text(locale, "Unable to complete this action.")
            );
            assert_eq!(
                for_visibility(false, locale, "Role assigned."),
                "Role assigned."
            );
        }
    }
}
