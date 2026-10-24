//! Activity achievements are separate from XP and preserve legacy unlocks.
use super::*;
use serde::Serialize;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AchievementProgress {
    pub id: String,
    pub name: String,
    pub description: String,
    pub value: i64,
    pub thresholds: Vec<i64>,
    pub unlocked: Vec<bool>,
}

const ACTIVITIES: &[(&str, &str, &str, &[i64])] = &[
    (
        "messages",
        "Conversation starter",
        "Send messages in the server",
        &[20, 100, 500, 1000],
    ),
    (
        "voice",
        "Stay awhile",
        "Spend minutes in voice channels",
        &[10, 60, 300, 600],
    ),
    (
        "reactions",
        "Reaction master",
        "Add reactions to messages",
        &[50, 250, 1000, 2000],
    ),
    (
        "threads_created",
        "Thread creator",
        "Create threads in the server",
        &[5, 25, 100, 200],
    ),
    (
        "threads_joined",
        "Thread explorer",
        "Join different threads",
        &[10, 50, 250, 500],
    ),
    ("boost", "Server supporter", "Boost the server", &[1]),
];

impl Store {
    pub fn achievement_statistics(
        &self,
        guild: &str,
    ) -> Result<(i64, std::collections::BTreeMap<String, i64>)> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let members=conn.query_row("SELECT COUNT(*) FROM (SELECT user_id FROM achievement_activity WHERE guild_id=?1 UNION SELECT user_id FROM achievements WHERE guild_id=?1 UNION SELECT user_id FROM levels WHERE guild_id=?1)",params![guild],|row| row.get(0))?;
        let mut stmt=conn.prepare("SELECT achievement_key,COUNT(*) FROM achievements WHERE guild_id=?1 GROUP BY achievement_key")?;
        let counts = stmt
            .query_map(params![guild], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<rusqlite::Result<std::collections::BTreeMap<_, _>>>()?;
        Ok((members, counts))
    }
    pub(super) fn migrate_achievement_activity(&self) -> Result<()> {
        self.conn.lock().expect("store mutex poisoned").execute_batch(
            "CREATE TABLE IF NOT EXISTS achievement_activity (guild_id TEXT NOT NULL,user_id TEXT NOT NULL,kind TEXT NOT NULL,value INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(guild_id,user_id,kind));
             CREATE TABLE IF NOT EXISTS achievement_events (guild_id TEXT NOT NULL,user_id TEXT NOT NULL,kind TEXT NOT NULL,event_key TEXT NOT NULL,PRIMARY KEY(guild_id,user_id,kind,event_key));
             CREATE TABLE IF NOT EXISTS achievement_voice (guild_id TEXT NOT NULL,user_id TEXT NOT NULL,channel_id TEXT NOT NULL,started_at INTEGER NOT NULL,PRIMARY KEY(guild_id,user_id));
             CREATE TABLE IF NOT EXISTS achievement_links (token_hash TEXT PRIMARY KEY,guild_id TEXT NOT NULL,user_id TEXT NOT NULL,name TEXT NOT NULL,avatar TEXT NOT NULL,expires_at INTEGER NOT NULL);
             CREATE INDEX IF NOT EXISTS achievement_links_expiry ON achievement_links(expires_at);
             CREATE TABLE IF NOT EXISTS achievement_threads (guild_id TEXT NOT NULL,channel_id TEXT NOT NULL,PRIMARY KEY(guild_id,channel_id));"
        )?;
        Ok(())
    }

    pub fn remember_achievement_thread(&self, guild: &str, channel: &str) -> Result<()> {
        self.conn.lock().expect("store mutex poisoned").execute(
            "INSERT OR IGNORE INTO achievement_threads VALUES(?1,?2)",
            params![guild, channel],
        )?;
        Ok(())
    }

    pub fn is_achievement_thread(&self, guild: &str, channel: &str) -> Result<bool> {
        Ok(self
            .conn
            .lock()
            .expect("store mutex poisoned")
            .query_row(
                "SELECT 1 FROM achievement_threads WHERE guild_id=?1 AND channel_id=?2",
                params![guild, channel],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .is_some())
    }

    /// Claims stop being stored once the final tier is reached, bounding growth.
    pub fn record_achievement_event(
        &self,
        guild: &str,
        user: &str,
        kind: &str,
        event: &str,
    ) -> Result<bool> {
        let cap = ACTIVITIES
            .iter()
            .find(|row| row.0 == kind)
            .and_then(|row| row.3.last())
            .copied()
            .ok_or_else(|| anyhow!("invalid achievement activity"))?;
        if guild.is_empty()
            || user.is_empty()
            || event.is_empty()
            || event.len() > 256
            || kind == "voice"
        {
            bail!("invalid achievement event");
        }
        let mut conn = self.conn.lock().expect("store mutex poisoned");
        let tx = conn.transaction()?;
        let value: i64 = tx.query_row("SELECT value FROM achievement_activity WHERE guild_id=?1 AND user_id=?2 AND kind=?3", params![guild,user,kind], |row| row.get(0)).optional()?.unwrap_or(0);
        if value >= cap
            || tx.execute(
                "INSERT OR IGNORE INTO achievement_events VALUES(?1,?2,?3,?4)",
                params![guild, user, kind, event],
            )? == 0
        {
            return Ok(false);
        }
        tx.execute("INSERT INTO achievement_activity VALUES(?1,?2,?3,1) ON CONFLICT(guild_id,user_id,kind) DO UPDATE SET value=value+1",params![guild,user,kind])?;
        tx.commit()?;
        Ok(true)
    }

    /// Keep seconds so short channel moves do not discard partial minutes.
    pub fn update_achievement_voice(
        &self,
        guild: &str,
        user: &str,
        channel: Option<&str>,
        now: i64,
    ) -> Result<()> {
        let mut conn = self.conn.lock().expect("store mutex poisoned");
        let tx = conn.transaction()?;
        let old: Option<(String,i64)> = tx.query_row("SELECT channel_id,started_at FROM achievement_voice WHERE guild_id=?1 AND user_id=?2",params![guild,user],|row| Ok((row.get(0)?,row.get(1)?))).optional()?;
        if old.as_ref().map(|row| row.0.as_str()) == channel {
            return Ok(());
        }
        if let Some((_, start)) = old {
            let seconds = now.saturating_sub(start).clamp(0, 86400);
            tx.execute("INSERT INTO achievement_activity VALUES(?1,?2,'voice',?3) ON CONFLICT(guild_id,user_id,kind) DO UPDATE SET value=MIN(36000,value+excluded.value)",params![guild,user,seconds])?;
        }
        tx.execute(
            "DELETE FROM achievement_voice WHERE guild_id=?1 AND user_id=?2",
            params![guild, user],
        )?;
        if let Some(channel) = channel {
            tx.execute(
                "INSERT INTO achievement_voice VALUES(?1,?2,?3,?4)",
                params![guild, user, channel, now],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn achievement_progress(
        &self,
        guild: &str,
        user: &str,
        now: i64,
    ) -> Result<Vec<AchievementProgress>> {
        let values = {
            let conn = self.conn.lock().expect("store mutex poisoned");
            let mut stmt = conn.prepare(
                "SELECT kind,value FROM achievement_activity WHERE guild_id=?1 AND user_id=?2",
            )?;
            stmt.query_map(params![guild, user], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })?
            .collect::<rusqlite::Result<std::collections::BTreeMap<_, _>>>()?
        };
        let active: Option<i64> = self
            .conn
            .lock()
            .expect("store mutex poisoned")
            .query_row(
                "SELECT started_at FROM achievement_voice WHERE guild_id=?1 AND user_id=?2",
                params![guild, user],
                |row| row.get(0),
            )
            .optional()?;
        let records = self.achievements_for(guild, user)?;
        let mut rows = Vec::new();
        for (id, name, description, thresholds) in ACTIVITIES {
            let mut value = *values.get(*id).unwrap_or(&0);
            if *id == "voice" {
                value = (value
                    + active.map_or(0, |start| now.saturating_sub(start).clamp(0, 86400)))
                    / 60;
            }
            rows.push(AchievementProgress {
                id: (*id).into(),
                name: (*name).into(),
                description: (*description).into(),
                value,
                thresholds: thresholds.to_vec(),
                unlocked: thresholds
                    .iter()
                    .enumerate()
                    .map(|(i, threshold)| {
                        value >= *threshold
                            || records
                                .iter()
                                .any(|row| row.achievement_key == format!("{id}:{}", i + 1))
                    })
                    .collect(),
            });
        }
        let thresholds = [
            ("first_threshold", 100),
            ("regular_threshold", 1000),
            ("pillar_threshold", 10000),
        ]
        .map(|(key, default)| {
            self.get_setting(guild, &format!("community.achievements.{key}"))
                .ok()
                .flatten()
                .and_then(|raw| raw.parse::<i64>().ok())
                .unwrap_or(default)
                .clamp(1, 1_000_000_000)
        });
        let xp = self.level_for(guild, user)?;
        let keys = ["first_steps", "regular", "community_pillar"];
        rows.push(AchievementProgress {
            id: "xp".into(),
            name: "XP milestones".into(),
            description: "Earn XP in the server".into(),
            value: xp,
            thresholds: thresholds.to_vec(),
            unlocked: thresholds
                .iter()
                .zip(keys)
                .map(|(threshold, key)| {
                    xp >= *threshold || records.iter().any(|row| row.achievement_key == key)
                })
                .collect(),
        });
        Ok(rows)
    }

    pub fn sync_activity_achievements(
        &self,
        guild: &str,
        user: &str,
        now: i64,
    ) -> Result<Vec<AchievementRecord>> {
        let mut unlocked = Vec::new();
        for row in self
            .achievement_progress(guild, user, now)?
            .iter()
            .filter(|row| row.id != "xp")
        {
            for (index, threshold) in row
                .thresholds
                .iter()
                .enumerate()
                .filter(|(_, threshold)| row.value >= **threshold)
            {
                let key = format!("{}:{}", row.id, index + 1);
                if self.unlock_achievement(
                    guild,
                    user,
                    &key,
                    *threshold,
                    now.saturating_mul(1000),
                )? {
                    unlocked.push(AchievementRecord {
                        guild_id: guild.into(),
                        user_id: user.into(),
                        achievement_key: key,
                        threshold: *threshold,
                        unlocked_at: now.saturating_mul(1000),
                    });
                }
            }
        }
        Ok(unlocked)
    }

    /// The personal link is scoped to one member, expires after an hour and rotates.
    pub fn create_achievement_link(
        &self,
        guild: &str,
        user: &str,
        name: &str,
        avatar: &str,
        now: i64,
    ) -> Result<String> {
        use sha2::{Digest, Sha256};
        let token = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        let hash = format!("{:x}", Sha256::digest(token.as_bytes()));
        let mut conn = self.conn.lock().expect("store mutex poisoned");
        let tx = conn.transaction()?;
        tx.execute(
            "DELETE FROM achievement_links WHERE expires_at<=?1 OR (guild_id=?2 AND user_id=?3)",
            params![now, guild, user],
        )?;
        tx.execute(
            "INSERT INTO achievement_links VALUES(?1,?2,?3,?4,?5,?6)",
            params![hash, guild, user, name, avatar, now + 3600],
        )?;
        tx.commit()?;
        Ok(token)
    }

    pub fn achievement_link(
        &self,
        guild: &str,
        token: &str,
        now: i64,
    ) -> Result<Option<(String, String, String)>> {
        use sha2::{Digest, Sha256};
        if token.len() != 64 || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Ok(None);
        }
        let hash = format!("{:x}", Sha256::digest(token.as_bytes()));
        self.conn.lock().expect("store mutex poisoned").query_row("SELECT user_id,name,avatar FROM achievement_links WHERE token_hash=?1 AND guild_id=?2 AND expires_at>?3",params![hash,guild,now],|row| Ok((row.get(0)?,row.get(1)?,row.get(2)?))).optional().map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn activities_are_deduplicated_scoped_and_preserve_legacy_unlocks() {
        let store = Store::open(":memory:").unwrap();
        store
            .unlock_achievement("g", "u", "regular", 1000, 1)
            .unwrap();
        for i in 0..20 {
            assert!(
                store
                    .record_achievement_event("g", "u", "messages", &i.to_string())
                    .unwrap()
            );
        }
        assert!(
            !store
                .record_achievement_event("g", "u", "messages", "0")
                .unwrap()
        );
        let unlocked = store.sync_activity_achievements("g", "u", 30).unwrap();
        assert_eq!(unlocked.len(), 1);
        assert_eq!(unlocked[0].achievement_key, "messages:1");
        assert!(
            store
                .sync_activity_achievements("g", "u", 31)
                .unwrap()
                .is_empty()
        );
        let rows = store.achievement_progress("g", "u", 30).unwrap();
        assert_eq!(rows[0].value, 20);
        assert_eq!(rows[0].unlocked, vec![true, false, false, false]);
        assert!(rows[6].unlocked[1]);
        assert_eq!(
            store.achievement_progress("other", "u", 30).unwrap()[0].value,
            0
        );
        assert_eq!(store.achievements_for("g", "u").unwrap().len(), 2);
        assert!(
            store
                .record_achievement_event("g", "u", "invalid", "1")
                .is_err()
        );
    }
    #[test]
    fn activity_unlocks_only_return_new_tiers_with_their_original_thresholds() {
        let store = Store::open(":memory:").unwrap();
        for i in 0..100 {
            store
                .record_achievement_event("g", "u", "messages", &i.to_string())
                .unwrap();
        }
        let unlocked = store.sync_activity_achievements("g", "u", 7).unwrap();
        assert_eq!(
            unlocked
                .iter()
                .map(|row| (row.achievement_key.as_str(), row.threshold, row.unlocked_at))
                .collect::<Vec<_>>(),
            vec![("messages:1", 20, 7000), ("messages:2", 100, 7000)]
        );
        assert!(
            store
                .sync_activity_achievements("g", "u", 8)
                .unwrap()
                .is_empty()
        );
        assert!(
            store
                .sync_activity_achievements("other", "u", 8)
                .unwrap()
                .is_empty()
        );
        assert!(
            store
                .sync_activity_achievements("g", "other", 8)
                .unwrap()
                .is_empty()
        );
        assert_eq!(store.level_for("g", "u").unwrap(), 0);
    }

    #[test]
    fn voice_moves_keep_seconds_and_duplicate_leaves_do_not_count_twice() {
        let store = Store::open(":memory:").unwrap();
        store
            .update_achievement_voice("g", "u", Some("c"), 0)
            .unwrap();
        store
            .update_achievement_voice("g", "u", Some("c"), 25)
            .unwrap();
        store
            .update_achievement_voice("g", "u", Some("d"), 35)
            .unwrap();
        assert_eq!(
            store.achievement_progress("g", "u", 65).unwrap()[1].value,
            1
        );
        store.update_achievement_voice("g", "u", None, 65).unwrap();
        store.update_achievement_voice("g", "u", None, 500).unwrap();
        assert_eq!(
            store.achievement_progress("g", "u", 500).unwrap()[1].value,
            1
        );
    }
    #[test]
    fn personal_links_expire_rotate_and_cannot_cross_guilds() {
        let store = Store::open(":memory:").unwrap();
        let first = store
            .create_achievement_link("g", "u", "Member", "", 100)
            .unwrap();
        assert!(store.achievement_link("g", &first, 100).unwrap().is_some());
        assert!(
            store
                .achievement_link("other", &first, 100)
                .unwrap()
                .is_none()
        );
        let second = store
            .create_achievement_link("g", "u", "Member", "", 101)
            .unwrap();
        assert!(store.achievement_link("g", &first, 102).unwrap().is_none());
        assert!(
            store
                .achievement_link("g", &second, 3701)
                .unwrap()
                .is_none()
        );
        assert!(store.achievement_link("g", "bad", 100).unwrap().is_none());
    }

    #[test]
    fn caps_privacy_exports_and_erasure_cover_the_new_storage() {
        let store = Store::open(":memory:").unwrap();
        for i in 0..1002 {
            store
                .record_achievement_event("g", "u", "messages", &i.to_string())
                .unwrap();
        }
        store
            .record_achievement_event("other", "u", "messages", "one")
            .unwrap();
        store.sync_activity_achievements("g", "u", 100).unwrap();
        let token = store
            .create_achievement_link("g", "u", "Name", "", 100)
            .unwrap();
        store.remember_achievement_thread("g", "thread").unwrap();
        assert!(store.is_achievement_thread("g", "thread").unwrap());
        assert!(!store.is_achievement_thread("other", "thread").unwrap());
        assert_eq!(
            store.achievement_progress("g", "u", 100).unwrap()[0].value,
            1000
        );
        assert_eq!(store.achievement_statistics("g").unwrap().0, 1);
        let export = store.export_user("g", "u").unwrap().to_string();
        assert!(export.contains("achievement_activity") && export.contains("messages:4"));
        assert!(!export.contains(&token));
        store.purge_user("g", "u").unwrap();
        assert!(store.achievement_link("g", &token, 100).unwrap().is_none());
        assert_eq!(
            store.achievement_progress("g", "u", 100).unwrap()[0].value,
            0
        );
        assert!(store.achievements_for("g", "u").unwrap().is_empty());
        assert_eq!(
            store.achievement_progress("other", "u", 100).unwrap()[0].value,
            1
        );
        store.purge_guild("g").unwrap();
        assert!(!store.is_achievement_thread("g", "thread").unwrap());
    }

    #[test]
    fn disabling_banks_voice_time_revokes_links_and_keeps_unlocks_atomically() {
        let store = Store::open(":memory:").unwrap();
        let now = Utc::now().timestamp();
        store
            .publish_feature_setting(
                "g",
                "community.achievements",
                true,
                "{}",
                None,
                "admin",
                &[],
            )
            .unwrap();
        store
            .update_achievement_voice("g", "u", Some("c"), now - 125)
            .unwrap();
        store
            .unlock_achievement("g", "u", "first_steps", 100, 1)
            .unwrap();
        let token = store
            .create_achievement_link("g", "u", "Name", "", now)
            .unwrap();
        assert!(
            store
                .publish_feature_setting(
                    "g",
                    "community.achievements",
                    false,
                    "{}",
                    Some(0),
                    "admin",
                    &[]
                )
                .is_err()
        );
        assert!(store.achievement_link("g", &token, now).unwrap().is_some());
        store
            .publish_feature_setting(
                "g",
                "community.achievements",
                false,
                "{}",
                Some(1),
                "admin",
                &[],
            )
            .unwrap();
        assert!(store.achievement_link("g", &token, now).unwrap().is_none());
        assert_eq!(
            store.achievement_progress("g", "u", now + 3600).unwrap()[1].value,
            2
        );
        assert_eq!(
            store.achievements_for("g", "u").unwrap()[0].achievement_key,
            "first_steps"
        );
    }
}
