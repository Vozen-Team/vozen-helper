use super::*;

pub struct PendingReminder {
    pub id: i64,
    pub target_id: String,
    pub execute_at: i64,
    pub payload: String,
}

impl Store {
    pub fn pending_reminders(&self, guild: &str, limit: u32) -> Result<Vec<PendingReminder>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let mut statement = conn.prepare("SELECT id,target_id,execute_at,payload FROM scheduled_actions WHERE guild_id=?1 AND type='reminder' ORDER BY execute_at,id LIMIT ?2")?;
        let rows = statement.query_map(params![guild, limit.clamp(1, 100)], |row| {
            Ok(PendingReminder {
                id: row.get(0)?,
                target_id: row.get(1)?,
                execute_at: row.get(2)?,
                payload: row.get(3)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn cancel_reminder(&self, guild: &str, id: i64) -> Result<bool> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        Ok(conn.execute(
            "DELETE FROM scheduled_actions WHERE guild_id=?1 AND id=?2 AND type='reminder'",
            params![guild, id],
        )? > 0)
    }
}
