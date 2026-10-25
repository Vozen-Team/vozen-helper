use super::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ShopProductInput {
    pub name: String,
    pub price: i64,
    pub delivery: String,
    pub role_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShopProduct {
    pub id: i64,
    pub name: String,
    pub price: i64,
    pub delivery: String,
    pub role_id: Option<String>,
    pub version: i64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ShopOrder {
    pub id: i64,
    pub user_id: String,
    pub display_name: String,
    pub product_name: String,
    pub price: i64,
    pub delivery: String,
    pub role_id: Option<String>,
    pub status: String,
    pub created_at: i64,
}

pub(super) fn migrate(conn: &Connection) -> Result<()> {
    conn.execute_batch("CREATE TABLE IF NOT EXISTS economy_products (
        id INTEGER PRIMARY KEY AUTOINCREMENT, guild_id TEXT NOT NULL,
        name TEXT NOT NULL, price INTEGER NOT NULL CHECK(price>0),
        delivery TEXT NOT NULL CHECK(delivery IN ('manual','role')), role_id TEXT,
        version INTEGER NOT NULL DEFAULT 1, active INTEGER NOT NULL DEFAULT 1);
        CREATE INDEX IF NOT EXISTS idx_economy_products_guild ON economy_products(guild_id,active,id);
        CREATE TABLE IF NOT EXISTS economy_orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT, guild_id TEXT NOT NULL, user_id TEXT NOT NULL,
        display_name TEXT NOT NULL, product_id INTEGER NOT NULL, product_name TEXT NOT NULL,
        price INTEGER NOT NULL CHECK(price>0), delivery TEXT NOT NULL, role_id TEXT,
        status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','delivered','refunded')),
        request_id TEXT NOT NULL UNIQUE, created_at INTEGER NOT NULL, resolved_by TEXT);
        CREATE INDEX IF NOT EXISTS idx_economy_orders_guild ON economy_orders(guild_id,id DESC);
        CREATE UNIQUE INDEX IF NOT EXISTS idx_economy_role_purchase
        ON economy_orders(guild_id,user_id,role_id) WHERE delivery='role' AND status!='refunded';")?;
    Ok(())
}

fn product(row: &rusqlite::Row<'_>) -> rusqlite::Result<ShopProduct> {
    Ok(ShopProduct {
        id: row.get(0)?,
        name: row.get(1)?,
        price: row.get(2)?,
        delivery: row.get(3)?,
        role_id: row.get(4)?,
        version: row.get(5)?,
    })
}
fn order(row: &rusqlite::Row<'_>) -> rusqlite::Result<ShopOrder> {
    Ok(ShopOrder {
        id: row.get(0)?,
        user_id: row.get(1)?,
        display_name: row.get(2)?,
        product_name: row.get(3)?,
        price: row.get(4)?,
        delivery: row.get(5)?,
        role_id: row.get(6)?,
        status: row.get(7)?,
        created_at: row.get(8)?,
    })
}
const ORDER_COLUMNS: &str =
    "id,user_id,display_name,product_name,price,delivery,role_id,status,created_at";

impl Store {
    pub fn shop_products(&self, guild: &str) -> Result<Vec<ShopProduct>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let mut stmt=conn.prepare("SELECT id,name,price,delivery,role_id,version FROM economy_products WHERE guild_id=?1 AND active=1 ORDER BY id LIMIT 20")?;
        Ok(stmt
            .query_map([guild], product)?
            .collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn save_shop_product(
        &self,
        guild: &str,
        id: Option<i64>,
        version: i64,
        input: &ShopProductInput,
    ) -> Result<()> {
        let name = input.name.trim();
        anyhow::ensure!(
            !name.is_empty() && name.chars().count() <= 60 && !name.chars().any(char::is_control),
            "shop_invalid_product"
        );
        anyhow::ensure!(
            (1..=1_000_000).contains(&input.price),
            "shop_invalid_product"
        );
        anyhow::ensure!(
            matches!(input.delivery.as_str(), "manual" | "role"),
            "shop_invalid_product"
        );
        anyhow::ensure!(
            if input.delivery == "role" {
                input
                    .role_id
                    .as_deref()
                    .is_some_and(|id| id.parse::<u64>().is_ok_and(|id| id > 0))
            } else {
                input.role_id.is_none()
            },
            "shop_invalid_product"
        );
        let mut conn = self.conn.lock().expect("store mutex poisoned");
        let tx = conn.transaction()?;
        if let Some(id) = id {
            anyhow::ensure!(tx.execute("UPDATE economy_products SET name=?3,price=?4,delivery=?5,role_id=?6,version=version+1 WHERE guild_id=?1 AND id=?2 AND version=?7 AND active=1",params![guild,id,name,input.price,input.delivery,input.role_id,version])?==1,"shop_changed");
        } else {
            let count: i64 = tx.query_row(
                "SELECT count(*) FROM economy_products WHERE guild_id=?1 AND active=1",
                [guild],
                |row| row.get(0),
            )?;
            anyhow::ensure!(count < 20, "shop_full");
            tx.execute("INSERT INTO economy_products(guild_id,name,price,delivery,role_id) VALUES(?1,?2,?3,?4,?5)",params![guild,name,input.price,input.delivery,input.role_id])?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn remove_shop_product(&self, guild: &str, id: i64, version: i64) -> Result<()> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        anyhow::ensure!(conn.execute("UPDATE economy_products SET active=0,version=version+1 WHERE guild_id=?1 AND id=?2 AND version=?3 AND active=1",params![guild,id,version])?==1,"shop_changed");
        Ok(())
    }

    pub fn shop_orders(&self, guild: &str, before: i64) -> Result<Vec<ShopOrder>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let mut stmt=conn.prepare(&format!("SELECT {ORDER_COLUMNS} FROM economy_orders WHERE guild_id=?1 AND id<?2 ORDER BY id DESC LIMIT 50"))?;
        Ok(stmt
            .query_map(params![guild, before], order)?
            .collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn buy_shop_product(
        &self,
        guild: &str,
        user: &str,
        display_name: &str,
        id: i64,
        version: i64,
        request: &str,
    ) -> Result<ShopOrder> {
        anyhow::ensure!(
            !request.is_empty() && request.len() <= 80,
            "shop_invalid_product"
        );
        let mut conn = self.conn.lock().expect("store mutex poisoned");
        let tx = conn.transaction()?;
        if let Some(order)=tx.query_row(&format!("SELECT {ORDER_COLUMNS} FROM economy_orders WHERE request_id=?1 AND guild_id=?2 AND user_id=?3"),params![request,guild,user],order).optional()? { return Ok(order); }
        let item=tx.query_row("SELECT id,name,price,delivery,role_id,version FROM economy_products WHERE guild_id=?1 AND id=?2 AND version=?3 AND active=1",params![guild,id,version],product).optional()?.ok_or_else(||anyhow!("shop_changed"))?;
        if item.delivery == "role" {
            let exists:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM economy_orders WHERE guild_id=?1 AND user_id=?2 AND role_id=?3 AND delivery='role' AND status!='refunded')",params![guild,user,item.role_id],|row|row.get(0))?;
            anyhow::ensure!(!exists, "shop_already_owned");
        }
        let now = Utc::now().timestamp_millis();
        // The conditional debit, purchase snapshot and ledger entry commit together.
        anyhow::ensure!(tx.execute("UPDATE economy_accounts SET balance=balance-?3,updated_at=?4 WHERE guild_id=?1 AND user_id=?2 AND balance>=?3",params![guild,user,item.price,now])?==1,"shop_insufficient");
        tx.execute("INSERT INTO economy_orders(guild_id,user_id,display_name,product_id,product_name,price,delivery,role_id,request_id,created_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",params![guild,user,display_name.chars().take(80).collect::<String>(),id,item.name,item.price,item.delivery,item.role_id,request,now])?;
        let order_id = tx.last_insert_rowid();
        tx.execute("INSERT INTO economy_ledger(guild_id,user_id,amount,reason,idempotency_key,created_at) VALUES(?1,?2,?3,?4,?5,?6)",params![guild,user,-item.price,format!("shop:{order_id}"),format!("shop:{request}"),now])?;
        let result = tx.query_row(
            &format!("SELECT {ORDER_COLUMNS} FROM economy_orders WHERE id=?1"),
            [order_id],
            order,
        )?;
        tx.commit()?;
        Ok(result)
    }

    pub fn resolve_shop_order(
        &self,
        guild: &str,
        id: i64,
        status: &str,
        actor: &str,
    ) -> Result<()> {
        anyhow::ensure!(
            matches!(status, "delivered" | "refunded"),
            "shop_invalid_product"
        );
        let mut conn = self.conn.lock().expect("store mutex poisoned");
        let tx = conn.transaction()?;
        let order = tx
            .query_row(
                &format!("SELECT {ORDER_COLUMNS} FROM economy_orders WHERE guild_id=?1 AND id=?2"),
                params![guild, id],
                order,
            )
            .optional()?
            .ok_or_else(|| anyhow!("shop_changed"))?;
        if order.status == status {
            return Ok(());
        }
        anyhow::ensure!(order.status == "pending", "shop_changed");
        if status == "refunded" {
            let now = Utc::now().timestamp_millis();
            anyhow::ensure!(tx.execute("UPDATE economy_accounts SET balance=balance+?3,updated_at=?4 WHERE guild_id=?1 AND user_id=?2 AND balance<=9223372036854775807-?3",params![guild,order.user_id,order.price,now])?==1,"shop_changed");
            tx.execute("INSERT INTO economy_ledger(guild_id,user_id,amount,reason,idempotency_key,created_at) VALUES(?1,?2,?3,?4,?5,?6)",params![guild,order.user_id,order.price,format!("refund:{id}"),format!("shop-refund:{id}"),now])?;
        }
        tx.execute("UPDATE economy_orders SET status=?3,resolved_by=?4 WHERE guild_id=?1 AND id=?2 AND status='pending'",params![guild,id,status,actor])?;
        tx.commit()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn item() -> ShopProductInput {
        ShopProductInput {
            name: "T-shirt".into(),
            price: 80,
            delivery: "manual".into(),
            role_id: None,
        }
    }
    #[test]
    fn purchase_is_scoped_versioned_atomic_and_idempotent() {
        let store = Store::open(":memory:").unwrap();
        store.claim_daily("g", "u", 100).unwrap();
        store.save_shop_product("g", None, 0, &item()).unwrap();
        let p = store.shop_products("g").unwrap().remove(0);
        assert!(
            store
                .buy_shop_product("other", "u", "Name", p.id, p.version, "a")
                .is_err()
        );
        assert!(
            store
                .buy_shop_product("g", "u", "Name", p.id, p.version + 1, "a")
                .is_err()
        );
        let order = store
            .buy_shop_product("g", "u", "Name", p.id, p.version, "a")
            .unwrap();
        assert_eq!(
            store
                .buy_shop_product("g", "u", "Name", p.id, p.version, "a")
                .unwrap()
                .id,
            order.id
        );
        assert_eq!(store.economy_account("g", "u").unwrap().balance, 20);
        assert!(
            store
                .buy_shop_product("g", "u", "Name", p.id, p.version, "b")
                .is_err()
        );
        assert_eq!(store.shop_orders("g", i64::MAX).unwrap().len(), 1);
        store.remove_shop_product("g", p.id, p.version).unwrap();
        assert!(store.shop_products("g").unwrap().is_empty());
        assert_eq!(
            store.shop_orders("g", i64::MAX).unwrap()[0].product_name,
            "T-shirt"
        );
        assert!(
            store
                .resolve_shop_order("other", order.id, "refunded", "staff")
                .is_err()
        );
        store
            .resolve_shop_order("g", order.id, "refunded", "staff")
            .unwrap();
        store
            .resolve_shop_order("g", order.id, "refunded", "staff")
            .unwrap();
        assert_eq!(store.economy_account("g", "u").unwrap().balance, 100);
        assert!(
            store
                .resolve_shop_order("g", order.id, "delivered", "staff")
                .is_err()
        );
    }
    #[test]
    fn invalid_products_and_duplicate_role_purchases_are_rejected() {
        let store = Store::open(":memory:").unwrap();
        let mut input = item();
        input.price = 0;
        assert!(store.save_shop_product("g", None, 0, &input).is_err());
        input.price = 10;
        input.delivery = "role".into();
        assert!(store.save_shop_product("g", None, 0, &input).is_err());
        input.role_id = Some("123".into());
        store.save_shop_product("g", None, 0, &input).unwrap();
        store.claim_daily("g", "u", 100).unwrap();
        let p = store.shop_products("g").unwrap().remove(0);
        let order = store
            .buy_shop_product("g", "u", "Name", p.id, p.version, "a")
            .unwrap();
        store
            .resolve_shop_order("g", order.id, "delivered", "bot")
            .unwrap();
        assert!(
            store
                .buy_shop_product("g", "u", "Name", p.id, p.version, "b")
                .is_err()
        );
        assert_eq!(store.economy_account("g", "u").unwrap().balance, 90);
    }
    #[test]
    fn simultaneous_purchases_cannot_overspend_and_erasure_covers_orders() {
        let store = Store::open(":memory:").unwrap();
        store.save_shop_product("g", None, 0, &item()).unwrap();
        let p = store.shop_products("g").unwrap().remove(0);
        store.claim_daily("g", "u", 100).unwrap();
        let handles = (0..8)
            .map(|index| {
                let store = store.clone();
                let p = p.clone();
                std::thread::spawn(move || {
                    store
                        .buy_shop_product("g", "u", "Name", p.id, p.version, &index.to_string())
                        .is_ok()
                })
            })
            .collect::<Vec<_>>();
        assert_eq!(
            handles
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .filter(|ok| *ok)
                .count(),
            1
        );
        assert_eq!(store.economy_account("g", "u").unwrap().balance, 20);
        store.delete_member_voluntary_data("g", "u").unwrap();
        assert!(store.shop_orders("g", i64::MAX).unwrap().is_empty());
        assert_eq!(store.shop_products("g").unwrap().len(), 1);
    }
}
