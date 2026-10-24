use super::achievement_card::{medal_color, medal_icon};
use super::suggestion_card::{escape, rasterize};
use helper_store::AchievementRecord;
use serenity::all::ChannelId;

pub(super) fn channel(
    key: &str,
    source: Option<ChannelId>,
    fallback: Option<ChannelId>,
) -> Option<ChannelId> {
    if key.starts_with("voice:") || key.starts_with("boost:") {
        fallback
    } else {
        source.or(fallback)
    }
}

struct Copy {
    heading: &'static str,
    names: [&'static str; 7],
    tiers: [&'static str; 4],
    units: [&'static str; 7],
}

fn copy(locale: &str) -> Copy {
    match locale {
        "pt" => Copy {
            heading: "Conquista desbloqueada!",
            names: [
                "À conversa",
                "Fica mais um pouco",
                "Mestre das reações",
                "Criador de tópicos",
                "Explorador de tópicos",
                "Apoiante do servidor",
                "Marcos de XP",
            ],
            tiers: ["Bronze", "Prata", "Ouro", "Diamante"],
            units: [
                "Mensagens",
                "Minutos em voz",
                "Reações",
                "Tópicos criados",
                "Tópicos com participação",
                "Impulsos",
                "XP",
            ],
        },
        "fr" => Copy {
            heading: "Succès débloqué !",
            names: [
                "À la discussion",
                "Reste un peu",
                "Maître des réactions",
                "Créateur de fils",
                "Explorateur de fils",
                "Soutien du serveur",
                "Paliers d’XP",
            ],
            tiers: ["Bronze", "Argent", "Or", "Diamant"],
            units: [
                "Messages",
                "Minutes en vocal",
                "Réactions",
                "Fils créés",
                "Fils rejoints",
                "Boosts",
                "XP",
            ],
        },
        "es" => Copy {
            heading: "¡Logro desbloqueado!",
            names: [
                "De charla",
                "Quédate un rato",
                "Maestro de reacciones",
                "Creador de hilos",
                "Explorador de hilos",
                "Apoyo del servidor",
                "Metas de XP",
            ],
            tiers: ["Bronce", "Plata", "Oro", "Diamante"],
            units: [
                "Mensajes",
                "Minutos en voz",
                "Reacciones",
                "Hilos creados",
                "Hilos con participación",
                "Mejoras",
                "XP",
            ],
        },
        "de" => Copy {
            heading: "Erfolg freigeschaltet!",
            names: [
                "Gesprächsstarter",
                "Bleib noch etwas",
                "Reaktionsmeister",
                "Thread-Ersteller",
                "Thread-Entdecker",
                "Server-Unterstützer",
                "XP-Meilensteine",
            ],
            tiers: ["Bronze", "Silber", "Gold", "Diamant"],
            units: [
                "Nachrichten",
                "Sprachminuten",
                "Reaktionen",
                "Erstellte Threads",
                "Threads mit Beteiligung",
                "Boosts",
                "XP",
            ],
        },
        "tr" => Copy {
            heading: "Başarım açıldı!",
            names: [
                "Sohbet başlatıcı",
                "Biraz daha kal",
                "Tepki ustası",
                "Konu oluşturucu",
                "Konu kaşifi",
                "Sunucu destekçisi",
                "XP hedefleri",
            ],
            tiers: ["Bronz", "Gümüş", "Altın", "Elmas"],
            units: [
                "Mesajlar",
                "Sesli dakika",
                "Tepkiler",
                "Oluşturulan konular",
                "Katılınan konular",
                "Takviyeler",
                "XP",
            ],
        },
        "ar" => Copy {
            heading: "تم فتح إنجاز!",
            names: [
                "بداية الحديث",
                "ابقَ قليلًا",
                "خبير التفاعلات",
                "منشئ المواضيع",
                "مستكشف المواضيع",
                "داعم الخادم",
                "مراحل XP",
            ],
            tiers: ["برونزي", "فضي", "ذهبي", "ماسي"],
            units: [
                "الرسائل",
                "دقائق الصوت",
                "التفاعلات",
                "المواضيع المنشأة",
                "المواضيع المشارَك فيها",
                "التعزيزات",
                "XP",
            ],
        },
        "zh" => Copy {
            heading: "成就已解鎖！",
            names: [
                "話題發起人",
                "多待一會",
                "反應達人",
                "討論串建立者",
                "討論串探索者",
                "伺服器支持者",
                "XP 里程碑",
            ],
            tiers: ["銅", "銀", "金", "鑽石"],
            units: [
                "訊息",
                "語音分鐘",
                "反應",
                "已建立討論串",
                "已參與討論串",
                "加成",
                "XP",
            ],
        },
        "ru" => Copy {
            heading: "Достижение открыто!",
            names: [
                "Начало разговора",
                "Останься ещё",
                "Мастер реакций",
                "Создатель веток",
                "Исследователь веток",
                "Поддержка сервера",
                "Рубежи XP",
            ],
            tiers: ["Бронза", "Серебро", "Золото", "Алмаз"],
            units: [
                "Сообщения",
                "Минуты в голосовых каналах",
                "Реакции",
                "Созданные ветки",
                "Ветки с участием",
                "Бусты",
                "XP",
            ],
        },
        "ko" => Copy {
            heading: "업적 달성!",
            names: [
                "대화의 시작",
                "조금 더 머물러요",
                "반응의 달인",
                "스레드 개설자",
                "스레드 탐험가",
                "서버 후원자",
                "XP 목표",
            ],
            tiers: ["브론즈", "실버", "골드", "다이아몬드"],
            units: [
                "메시지",
                "음성 채널 시간(분)",
                "반응",
                "개설한 스레드",
                "참여한 스레드",
                "부스트",
                "XP",
            ],
        },
        _ => Copy {
            heading: "Achievement unlocked!",
            names: [
                "Conversation starter",
                "Stay awhile",
                "Reaction master",
                "Thread creator",
                "Thread explorer",
                "Server supporter",
                "XP milestones",
            ],
            tiers: ["Bronze", "Silver", "Gold", "Diamond"],
            units: [
                "Messages",
                "Voice minutes",
                "Reactions",
                "Threads created",
                "Threads joined",
                "Boosts",
                "XP",
            ],
        },
    }
}

pub(super) fn content(
    user: &str,
    record: &AchievementRecord,
    locale: &str,
) -> Option<(String, String)> {
    let (id, tier) = match record.achievement_key.as_str() {
        "first_steps" => ("xp", 1),
        "regular" => ("xp", 2),
        "community_pillar" => ("xp", 3),
        key => {
            let (id, tier) = key.rsplit_once(':')?;
            (id, tier.parse::<usize>().ok()?)
        }
    };
    let index = [
        "messages",
        "voice",
        "reactions",
        "threads_created",
        "threads_joined",
        "boost",
        "xp",
    ]
    .iter()
    .position(|key| *key == id)?;
    if !(1..=4).contains(&tier) {
        return None;
    }
    let copy = copy(locale);
    let name = copy.names[index];
    let tier_name = copy.tiers[tier - 1];
    let color = medal_color(tier);
    let icon = medal_icon(id);
    let heading = escape(copy.heading);
    let title = escape(&format!("{name} ({tier_name})"));
    let goal = escape(&format!("{}: {}", copy.units[index], record.threshold));
    let caption = format!("🎉 <@{user}> · {} **{name} ({tier_name})**", copy.heading);
    let svg = format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" width="900" height="210" viewBox="0 0 900 210"><rect x="2" y="2" width="896" height="206" rx="18" fill="#101A29" stroke="{color}" stroke-width="3"/><path d="M400 2L570 208M540 2L710 208" stroke="#192A3B" stroke-width="30" opacity=".45"/><g transform="translate(105 105) scale(1.35)"><path d="M0-48L42-24V24L0 48L-42 24V-24Z" fill="{color}" fill-opacity=".18" stroke="{color}" stroke-width="3"/><path d="{icon}" fill="none" stroke="{color}" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"/></g><g font-family="sans-serif"><text x="205" y="58" fill="{color}" font-size="18">{heading}</text><text x="205" y="105" fill="#F4F7FB" font-size="30" font-weight="700">{title}</text><text x="205" y="158" fill="#AAB8CB" font-size="20">{goal}</text></g></svg>"##
    );
    Some((caption, svg))
}

pub(super) async fn image(svg: String) -> Option<Vec<u8>> {
    tokio::task::spawn_blocking(move || rasterize(&svg))
        .await
        .ok()
        .flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn announcements_use_activity_channels_and_voice_uses_the_configured_channel() {
        let source = Some(ChannelId::new(1));
        let fallback = Some(ChannelId::new(2));
        for key in [
            "messages:1",
            "reactions:2",
            "threads_created:1",
            "threads_joined:1",
            "regular",
        ] {
            assert_eq!(channel(key, source, fallback), source);
            assert_eq!(channel(key, None, fallback), fallback);
        }
        for key in ["voice:1", "boost:1"] {
            assert_eq!(channel(key, source, fallback), fallback);
            assert_eq!(channel(key, source, None), None);
        }
    }

    #[test]
    fn unlock_card_covers_the_site_languages_and_legacy_xp_keys() {
        let mut record = AchievementRecord {
            guild_id: "g".into(),
            user_id: "u".into(),
            achievement_key: "messages:1".into(),
            threshold: 20,
            unlocked_at: 1,
        };
        for locale in super::super::HELPER_LOCALES {
            let (caption, svg) = content("123", &record, locale.0).unwrap();
            assert!(caption.contains("<@123>"));
            assert!(svg.contains(medal_color(1)));
            assert!(svg.contains(copy(locale.0).names[0]));
            assert!(svg.contains("20"));
            if locale.0 != "en" {
                assert!(!svg.contains("Achievement unlocked!"));
            }
            if let Ok(path) = std::env::var("HELPER_ACHIEVEMENT_UNLOCK_PREVIEW") {
                let path = std::path::PathBuf::from(path)
                    .with_file_name(format!("achievement-unlocked-{}.png", locale.0));
                std::fs::write(path, rasterize(&svg).unwrap()).unwrap();
            }
        }
        let (_, svg) = content("123", &record, "pt").unwrap();
        let png = rasterize(&svg).unwrap();
        let pixels = resvg::tiny_skia::Pixmap::decode_png(&png).unwrap();
        assert_eq!((pixels.width(), pixels.height()), (900, 210));
        if let Ok(path) = std::env::var("HELPER_ACHIEVEMENT_UNLOCK_PREVIEW") {
            std::fs::write(path, png).unwrap();
        }
        for key in ["first_steps", "regular", "community_pillar"] {
            record.achievement_key = key.into();
            assert!(content("123", &record, "en").is_some());
        }
        for key in ["messages:0", "messages:5", "invalid:1", "messages:bad"] {
            record.achievement_key = key.into();
            assert!(content("123", &record, "en").is_none());
        }
    }
}
