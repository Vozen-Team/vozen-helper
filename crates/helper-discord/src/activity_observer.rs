use helper_store::Store;
use serenity::all::{AuditLogEntry, CommandInteraction};

pub(super) fn command(store: &Store, command: &CommandInteraction, bot: u64, outcome: &str) {
    // Do not recreate an identifiable activity row immediately after a privacy purge.
    if command.data.name == "privacy" {
        return;
    }
    if let Some(guild) = command.guild_id {
        let actor = (bot > 0).then(|| bot.to_string());
        let detail = serde_json::json!({"command":command.data.name,"outcome":outcome});
        let _ = store.record_activity(
            &guild.to_string(),
            "helper_command",
            &command.user.id.to_string(),
            Some(
                command
                    .user
                    .global_name
                    .as_deref()
                    .unwrap_or(&command.user.name),
            ),
            actor.as_deref(),
            &detail.to_string(),
        );
    }
}

pub(super) fn audit(store: &Store, guild: &str, entry: &AuditLogEntry, bot: u64) {
    use serenity::model::guild::audit_log::Change;
    let by_helper = bot > 0 && entry.user_id.get() == bot;
    let timeout = entry.changes.as_ref().and_then(|changes| {
        changes.iter().find_map(|change| match change {
            Change::CommunicationDisabledUntil { new, .. } => {
                Some(new.as_ref().map(|value| value.unix_timestamp()))
            }
            _ => None,
        })
    });
    let kind = match entry.action.num() {
        22 => "member_ban",
        23 => "member_unban",
        24 if timeout.is_some() => {
            if timeout.flatten().is_some() {
                "member_timeout"
            } else {
                "member_timeout_end"
            }
        }
        _ if by_helper => "helper_action",
        _ => return,
    };
    let user = if kind == "helper_action" {
        entry.user_id.to_string()
    } else if let Some(id) = entry.target_id {
        id.to_string()
    } else {
        return;
    };
    let detail = serde_json::json!({"event_id":entry.id.to_string(),"by_helper":by_helper,"action":entry.action.num(),"target_id":entry.target_id.map(|id|id.to_string()),"reason":entry.reason.as_ref().map(|reason|reason.chars().take(512).collect::<String>()),"until":timeout.flatten()});
    if let Err(error) = store.record_observed_activity(
        guild,
        kind,
        &user,
        None,
        Some(&entry.user_id.to_string()),
        &detail.to_string(),
    ) {
        tracing::warn!(%error,"activity observation failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn audit_captures_manual_moderation_and_helper_actions_without_anti_nuke() {
        let store = Store::open(":memory:").unwrap();
        for (id, action, actor, changes) in [
            ("100", 22, "10", serde_json::json!([])),
            (
                "101",
                24,
                "10",
                serde_json::json!([{"key":"communication_disabled_until","new_value":"2026-10-25T10:00:00Z"}]),
            ),
            ("102", 10, "99", serde_json::json!([])),
        ] {
            let entry:AuditLogEntry=serde_json::from_value(serde_json::json!({"id":id,"action_type":action,"user_id":actor,"target_id":"20","changes":changes})).unwrap();
            audit(&store, "g", &entry, 99);
            audit(&store, "g", &entry, 99);
        }
        assert_eq!(
            store.activity_feed("g", "bans", None, 100).unwrap().len(),
            1
        );
        assert_eq!(
            store
                .activity_feed("g", "timeouts", None, 100)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            store.activity_feed("g", "helper", None, 100).unwrap().len(),
            1
        );
    }
}
