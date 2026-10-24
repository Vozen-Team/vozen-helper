use super::*;

#[derive(Debug, Clone, serde::Serialize)]
pub struct ActivityFeedRecord {
    pub id: String,
    pub source: String,
    pub kind: String,
    pub user_id: String,
    pub user_tag: Option<String>,
    pub actor_id: Option<String>,
    pub detail: String,
    pub outcome: String,
    pub created_at: i64,
    pub category: String,
    pub helper: bool,
    #[serde(skip)]
    pub sort_source: i64,
    #[serde(skip)]
    pub row_id: i64,
}

impl ActivityFeedRecord {
    pub fn cursor(&self) -> String {
        format!("{}:{}:{}", self.created_at, self.sort_source, self.row_id)
    }
}

impl Store {
    pub fn activity_feed(
        &self,
        guild: &str,
        category: &str,
        before: Option<(i64, i64, i64)>,
        limit: u32,
    ) -> Result<Vec<ActivityFeedRecord>> {
        if !["all", "joins", "leaves", "bans", "timeouts", "helper"].contains(&category) {
            bail!("invalid activity category");
        }
        let conn = self.conn.lock().expect("store mutex poisoned");
        let mut query = conn.prepare(r#"
          WITH records AS (
            SELECT id AS row_id, 0 AS source, type AS kind, user_id, user_tag, actor_id, detail,
              CASE WHEN type='helper_message' THEN 'sent' WHEN type='helper_message_edit' THEN 'updated' WHEN type='helper_command' AND json_valid(detail) THEN COALESCE(json_extract(detail,'$.outcome'),'recorded') ELSE 'recorded' END AS outcome,
              created_at, (type GLOB 'helper_*' OR CASE WHEN json_valid(detail) THEN COALESCE(json_extract(detail,'$.by_helper'),0) ELSE 0 END) AS helper
            FROM activity_log WHERE guild_id=?1
            UNION ALL
            SELECT id, 1, type, target_id, NULL, moderator_id, reason,
              CASE WHEN type IN ('anti-spam','anti-scam','anti_nuke_audit') THEN 'detected' ELSE 'recorded' END, created_at, 1
            FROM cases WHERE guild_id=?1
            UNION ALL
            SELECT id, 2, action, actor_id, NULL, actor_id, reason, outcome, created_at, 1
            FROM audit_events WHERE guild_id=?1
          ), classified AS (
            SELECT *, CASE
              WHEN kind IN ('member_join','join') THEN 'joins'
              WHEN kind IN ('member_leave','leave') THEN 'leaves'
              WHEN kind IN ('ban','unban','softban','tempban','member_ban','member_unban') THEN 'bans'
              WHEN kind IN ('timeout','untimeout','mute','unmute','member_timeout','member_timeout_end') THEN 'timeouts'
              ELSE 'other' END AS category
            FROM records
          )
          SELECT row_id,source,kind,user_id,user_tag,actor_id,detail,outcome,created_at,category,helper FROM classified r
          WHERE (?2='all' OR (?2='helper' AND helper=1) OR category=?2)
            AND (?3 IS NULL OR (created_at,source,row_id)<(?3,?4,?5))
            AND NOT (source=0 AND helper=1 AND kind IN ('member_ban','member_unban','member_timeout','member_timeout_end')
              AND EXISTS (SELECT 1 FROM cases c WHERE c.guild_id=?1 AND c.target_id=r.user_id
                AND ABS(c.created_at-r.created_at)<=15000
                AND ((r.kind='member_ban' AND c.type IN ('ban','softban','tempban')) OR (r.kind='member_unban' AND c.type='unban')
                  OR (r.kind='member_timeout' AND c.type IN ('timeout','mute')) OR (r.kind='member_timeout_end' AND c.type IN ('untimeout','unmute')))))
          ORDER BY created_at DESC, source DESC, row_id DESC LIMIT ?6
        "#)?;
        let rows = query.query_map(
            params![
                guild,
                category,
                before.map(|v| v.0),
                before.map(|v| v.1),
                before.map(|v| v.2),
                limit.clamp(1, 101)
            ],
            |row| {
                let row_id: i64 = row.get(0)?;
                let source: i64 = row.get(1)?;
                let source_name = ["activity", "case", "audit"][source as usize];
                Ok(ActivityFeedRecord {
                    id: format!("{source_name}:{row_id}"),
                    source: source_name.into(),
                    sort_source: source,
                    row_id,
                    kind: row.get(2)?,
                    user_id: row.get(3)?,
                    user_tag: row.get(4)?,
                    actor_id: row.get(5)?,
                    detail: row.get(6)?,
                    outcome: row.get(7)?,
                    created_at: row.get(8)?,
                    category: row.get(9)?,
                    helper: row.get(10)?,
                })
            },
        )?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    pub fn activity_member_name(&self, guild: &str, user: &str) -> Result<Option<String>> {
        self.conn.lock().expect("store mutex poisoned").query_row(
            "SELECT user_tag FROM activity_log WHERE guild_id=?1 AND user_id=?2 AND user_tag IS NOT NULL AND user_tag<>'' ORDER BY id DESC LIMIT 1",params![guild,user], |row|row.get(0)).optional().map_err(Into::into)
    }

    // Gateway observations and audit entries can describe the same change. Enrich
    // that observation with its actor instead of adding another visible event.
    pub fn record_observed_activity(
        &self,
        guild: &str,
        kind: &str,
        user: &str,
        tag: Option<&str>,
        actor: Option<&str>,
        detail: &str,
    ) -> Result<bool> {
        let metadata: serde_json::Value = serde_json::from_str(detail)?;
        if !metadata.is_object() || detail.chars().count() > 2000 {
            bail!("invalid activity metadata");
        }
        let group = match kind {
            "member_ban" | "member_unban" => "ban",
            "member_timeout" | "member_timeout_end" => "timeout",
            _ => kind,
        };
        let now = Utc::now().timestamp_millis();
        let conn = self.conn.lock().expect("store mutex poisoned");
        let previous:Option<(i64,String,String,i64)>=conn.query_row(
            "SELECT id,type,detail,created_at FROM activity_log WHERE guild_id=?1 AND user_id=?2 AND (type=?3 OR (?4='ban' AND type IN ('member_ban','member_unban')) OR (?4='timeout' AND type IN ('member_timeout','member_timeout_end'))) ORDER BY id DESC LIMIT 1",params![guild,user,kind,group],|row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?))).optional()?;
        if let Some((id, previous_kind, previous_detail, at)) = previous {
            let mut previous: serde_json::Value =
                serde_json::from_str::<serde_json::Value>(&previous_detail)
                    .ok()
                    .filter(serde_json::Value::is_object)
                    .unwrap_or(serde_json::json!({}));
            let same = previous_kind == kind
                && if group == "timeout" {
                    previous["until"] == metadata["until"]
                } else if group == "ban" {
                    now.saturating_sub(at) < 10000
                } else if let Some(event) = metadata.get("event_id") {
                    previous.get("event_id") == Some(event)
                } else {
                    now.saturating_sub(at) < 10000
                };
            if same {
                if let Some(object) = metadata.as_object() {
                    for (key, value) in object {
                        if !value.is_null() {
                            previous[key] = value.clone();
                        }
                    }
                }
                conn.execute("UPDATE activity_log SET user_tag=COALESCE(?2,user_tag),actor_id=COALESCE(?3,actor_id),detail=?4 WHERE id=?1",params![id,tag,actor,previous.to_string()])?;
                return Ok(false);
            }
        }
        conn.execute("INSERT INTO activity_log(guild_id,type,user_id,user_tag,actor_id,detail,created_at) VALUES(?1,?2,?3,?4,?5,?6,?7)",params![guild,kind,user,tag,actor,detail.chars().take(2000).collect::<String>(),now])?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn feed_filters_all_sources_pages_ties_and_keeps_guilds_isolated() {
        let store = Store::open(":memory:").unwrap();
        store
            .record_activity("g", "member_join", "u", Some("Member"), None, "{}")
            .unwrap();
        store
            .record_activity("g", "member_leave", "v", Some("Other"), None, "{}")
            .unwrap();
        store
            .record_case("g", "ban", "u", "mod", "reason", None)
            .unwrap();
        store
            .record_case("other", "ban", "secret", "mod", "private", None)
            .unwrap();
        store
            .record_activity("g", "helper_message", "bot", Some("Helper"), None, "{}")
            .unwrap();
        {
            let conn = store.conn.lock().unwrap();
            conn.execute("INSERT INTO audit_events(correlation_id,guild_id,actor_id,action,reason,before_json,after_json,outcome,created_at) VALUES('test','g','mod','settings','reason','{}','{}','succeeded',1)",[]).unwrap();
            conn.execute("UPDATE cases SET created_at=1 WHERE guild_id='g'", [])
                .unwrap();
            conn.execute(
                "UPDATE activity_log SET created_at=1 WHERE guild_id='g'",
                [],
            )
            .unwrap();
        }
        let all = store.activity_feed("g", "all", None, 100).unwrap();
        assert_eq!(all.len(), 5);
        assert_eq!(
            store.activity_feed("g", "joins", None, 100).unwrap().len(),
            1
        );
        assert_eq!(
            store.activity_feed("g", "leaves", None, 100).unwrap().len(),
            1
        );
        assert_eq!(
            store.activity_feed("g", "bans", None, 100).unwrap().len(),
            1
        );
        assert_eq!(
            store.activity_feed("g", "helper", None, 100).unwrap().len(),
            3
        );
        let first = store.activity_feed("g", "all", None, 2).unwrap();
        let last = first.last().unwrap();
        let second = store
            .activity_feed(
                "g",
                "all",
                Some((last.created_at, last.sort_source, last.row_id)),
                100,
            )
            .unwrap();
        assert_eq!(
            first
                .iter()
                .chain(&second)
                .map(|r| &r.id)
                .collect::<Vec<_>>(),
            all.iter().map(|r| &r.id).collect::<Vec<_>>()
        );
        assert!(store.activity_feed("g", "invalid", None, 100).is_err());
        assert_eq!(
            store.activity_member_name("g", "u").unwrap().as_deref(),
            Some("Member")
        );
        assert!(store.activity_member_name("other", "u").unwrap().is_none());
    }

    #[test]
    fn observations_preserve_changes_and_enrich_duplicate_timeout_actors() {
        let store = Store::open(":memory:").unwrap();
        assert!(
            store
                .record_observed_activity(
                    "g",
                    "member_timeout",
                    "u",
                    Some("Name"),
                    None,
                    r#"{"until":100}"#
                )
                .unwrap()
        );
        assert!(
            !store
                .record_observed_activity(
                    "g",
                    "member_timeout",
                    "u",
                    Some("Name"),
                    Some("mod"),
                    r#"{"until":100,"event_id":"audit"}"#
                )
                .unwrap()
        );
        assert_eq!(
            store.recent_activity("g", 10).unwrap()[0]
                .actor_id
                .as_deref(),
            Some("mod")
        );
        assert!(
            store
                .record_observed_activity(
                    "g",
                    "member_timeout_end",
                    "u",
                    Some("Name"),
                    Some("mod"),
                    r#"{"until":null}"#
                )
                .unwrap()
        );
        assert!(
            store
                .record_observed_activity(
                    "g",
                    "member_timeout",
                    "u",
                    Some("Name"),
                    None,
                    r#"{"until":100}"#
                )
                .unwrap()
        );
        assert_eq!(
            store
                .activity_feed("g", "timeouts", None, 100)
                .unwrap()
                .len(),
            3
        );
    }
    #[test]
    fn helper_moderation_case_and_gateway_observation_are_one_visible_action() {
        let store = Store::open(":memory:").unwrap();
        store
            .record_case("g", "ban", "u", "mod", "reason", None)
            .unwrap();
        store
            .record_observed_activity(
                "g",
                "member_ban",
                "u",
                Some("Member"),
                Some("bot"),
                r#"{"by_helper":true}"#,
            )
            .unwrap();
        let feed = store.activity_feed("g", "bans", None, 100).unwrap();
        assert_eq!(feed.len(), 1);
        assert_eq!(feed[0].source, "case");
        assert_eq!(
            store.recent_activity("g", 100).unwrap().len(),
            1,
            "source evidence remains stored"
        );
    }
}
