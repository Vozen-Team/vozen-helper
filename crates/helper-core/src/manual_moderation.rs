//! Permission and hierarchy boundary for human-requested member moderation.

const ADMINISTRATOR: u64 = 1 << 3;
const MODERATE_MEMBERS: u64 = 1 << 40;
const MANAGE_ROLES: u64 = 1 << 28;

#[derive(Debug, Clone, Copy)]
pub struct ActionPermissions {
    pub actor: u64,
    pub bot: u64,
}

#[must_use]
pub fn permissions(action: &str) -> Option<ActionPermissions> {
    let (actor, bot) = match action {
        "warn" | "violation" | "note" => (MODERATE_MEMBERS, 0),
        "kick" => (1 << 1, 1 << 1),
        "ban" | "tempban" | "softban" | "unban" => (1 << 2, 1 << 2),
        "timeout" | "untimeout" => (MODERATE_MEMBERS, MODERATE_MEMBERS),
        "quarantine" | "unquarantine" => (MODERATE_MEMBERS | MANAGE_ROLES, MANAGE_ROLES),
        _ => return None,
    };
    Some(ActionPermissions { actor, bot })
}

#[derive(Debug, Clone, Copy)]
pub struct Authority {
    pub actor_id: u64,
    pub target_id: u64,
    pub owner_id: u64,
    pub actor_permissions: u64,
    pub actor_top: i64,
    pub bot_permissions: u64,
    pub bot_top: i64,
    /// Only a verified Discord member-lookup 404 may produce `None`.
    pub target_top: Option<i64>,
    pub target_administrator: bool,
}

fn has_permissions(bits: u64, required: u64) -> bool {
    bits & ADMINISTRATOR != 0 || bits & required == required
}

#[must_use]
pub fn allowed(action: &str, authority: &Authority) -> bool {
    let Some(required) = permissions(action) else {
        return false;
    };
    let owner = authority.actor_id == authority.owner_id;
    if authority.actor_id == 0
        || authority.target_id == 0
        || authority.owner_id == 0
        || authority.actor_id == authority.target_id
        || authority.target_id == authority.owner_id
        || (!owner && !has_permissions(authority.actor_permissions, required.actor))
        || !has_permissions(authority.bot_permissions, required.bot)
    {
        return false;
    }
    match authority.target_top {
        Some(target) => {
            target >= 0
                && target < authority.bot_top
                && (owner || target < authority.actor_top)
                && (action != "timeout" || !authority.target_administrator)
        }
        None => matches!(action, "ban" | "tempban" | "softban" | "unban"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn moderator() -> Authority {
        Authority {
            actor_id: 2,
            target_id: 3,
            owner_id: 1,
            actor_permissions: u64::MAX,
            actor_top: 5,
            bot_permissions: u64::MAX,
            bot_top: 10,
            target_top: Some(4),
            target_administrator: false,
        }
    }

    #[test]
    fn hierarchy_is_strict_for_every_manual_target_action() {
        for action in [
            "warn",
            "violation",
            "note",
            "kick",
            "ban",
            "tempban",
            "softban",
            "unban",
            "timeout",
            "untimeout",
            "quarantine",
            "unquarantine",
        ] {
            let mut authority = moderator();
            assert!(allowed(action, &authority), "{action}");
            authority.target_top = Some(5);
            assert!(!allowed(action, &authority), "{action}");
            authority.actor_id = authority.owner_id;
            assert!(allowed(action, &authority), "{action}");
            authority.target_top = Some(10);
            assert!(!allowed(action, &authority), "{action}");
            authority = moderator();
            authority.target_id = authority.owner_id;
            assert!(!allowed(action, &authority));
            authority = moderator();
            authority.target_id = authority.actor_id;
            assert!(!allowed(action, &authority));
        }
    }

    #[test]
    fn absent_targets_and_action_permissions_are_distinguished() {
        let mut authority = moderator();
        authority.target_top = None;
        assert!(allowed("ban", &authority));
        assert!(!allowed("kick", &authority));
        assert!(!allowed("timeout", &authority));
        authority = moderator();
        authority.actor_permissions = MODERATE_MEMBERS;
        assert!(allowed("warn", &authority));
        assert!(allowed("timeout", &authority));
        assert!(!allowed("ban", &authority));
        assert!(!allowed("quarantine", &authority));
        authority = moderator();
        authority.bot_permissions = 1 << 28;
        assert!(allowed("quarantine", &authority));
        assert!(!allowed("timeout", &authority));
        authority = moderator();
        authority.target_administrator = true;
        assert!(!allowed("timeout", &authority));
    }
}
