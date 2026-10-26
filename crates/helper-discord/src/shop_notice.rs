use super::*;
use helper_store::{ScheduledAction, ShopOrder};
use serde_json::{Value, json};

fn body(order: &ShopOrder, currency: &str, locale: &str) -> Value {
    let (title, button) = match locale {
        "pt" => ("Novo pedido · entrega manual", "Ver loja"),
        "fr" => ("Nouvelle commande · livraison manuelle", "Voir la boutique"),
        "es" => ("Nuevo pedido · entrega manual", "Ver tienda"),
        "de" => ("Neue Bestellung · manuelle Lieferung", "Shop öffnen"),
        "tr" => ("Yeni sipariş · ekip teslimatı", "Mağazayı aç"),
        "ar" => ("طلب جديد · تسليم يدوي", "فتح المتجر"),
        "zh" => ("新訂單 · 人工交付", "查看商店"),
        "ru" => ("Новый заказ · выдача персоналом", "Открыть магазин"),
        "ko" => ("새 주문 · 운영진 지급", "상점 보기"),
        _ => ("New order · staff delivery", "Open shop"),
    };
    json!({"embeds":[{"title":title,"description":format!("**{}** · {} {}\n<@{}> · {}\n**#{}**",super::economy_shop::safe(&order.product_name),order.price,super::economy_shop::safe(currency),order.user_id,super::economy_shop::safe(&order.display_name),order.id),"color":0x8ee5d2}],
        "allowed_mentions":{"parse":[]},"nonce":format!("shop-{}",order.id),"enforce_nonce":true,
        "components":[{"type":1,"components":[{"type":2,"style":5,"label":button,"url":"https://vozen.org/panel/helper-tracker/#/config/community.economy"}]}]})
}

pub(super) async fn deliver(
    base: &str,
    token: &str,
    store: &Store,
    job: &ScheduledAction,
) -> Result<()> {
    let (id, guild, _, target, raw) = job;
    let Some(order) = target
        .parse::<i64>()
        .ok()
        .map(|id| store.shop_order(guild, id))
        .transpose()?
        .flatten()
    else {
        return store.delete_scheduled_action(*id);
    };
    if order.delivery != "manual" || order.status != "pending" {
        return store.delete_scheduled_action(*id);
    }
    let channel = store
        .get_setting(guild, "community.economy.staff_channel")?
        .unwrap_or_default();
    if channel.parse::<u64>().is_err() || channel == "0" {
        return store.delete_scheduled_action(*id);
    }
    let now = Utc::now().timestamp_millis();
    let mut state: Value = serde_json::from_str(raw)?;
    if let Some(at) = state["attempted_at"].as_i64()
        && (now - at >= 120_000 || state["notice_channel"].as_str() != Some(&channel))
    {
        // Discord nonce deduplication is short-lived. An old unknown result needs staff review.
        state["failed"] = json!(true);
        store.shop_notice_state(*id, &state.to_string(), i64::MAX)?;
        return Ok(());
    }
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .build()?;
    // Verify the destination still belongs to this server before posting purchase details.
    let info = match client
        .get(format!("{base}/channels/{channel}"))
        .header("Authorization", token)
        .send()
        .await
    {
        Ok(info) => info,
        Err(_) => {
            state["failed"] = json!(true);
            store.shop_notice_state(*id, &state.to_string(), now + 60_000)?;
            return Ok(());
        }
    };
    if !info.status().is_success() {
        state["failed"] = json!(true);
        store.shop_notice_state(*id, &state.to_string(), now + 60_000)?;
        return Ok(());
    }
    let info: Value = info.json().await?;
    if info["guild_id"].as_str() != Some(guild) || !matches!(info["type"].as_u64(), Some(0 | 5)) {
        state["failed"] = json!(true);
        store.shop_notice_state(*id, &state.to_string(), i64::MAX)?;
        return Ok(());
    }
    state["notice_channel"] = json!(channel);
    if state["attempted_at"].is_null() {
        state["attempted_at"] = json!(now);
    }
    state["failed"] = json!(false);
    if !store.shop_notice_state(*id, &state.to_string(), now + 5_000)? {
        return Ok(());
    }
    let currency = store
        .get_setting(guild, "community.economy.currency_name")?
        .unwrap_or_else(|| "credits".into());
    let locale = helper_locale_for_guild(store, guild).unwrap_or(DEFAULT_HELPER_LOCALE);
    let response = client
        .post(format!("{base}/channels/{channel}/messages"))
        .header("Authorization", token)
        .json(&body(&order, &currency, locale))
        .send()
        .await;
    match response {
        Ok(response) if response.status().is_success() => store.delete_scheduled_action(*id)?,
        other => {
            if let Ok(response) = other
                && response.status().is_client_error()
                && response.status() != reqwest::StatusCode::REQUEST_TIMEOUT
            {
                state["attempted_at"] = Value::Null;
            }
            state["failed"] = json!(true);
            store.shop_notice_state(*id, &state.to_string(), now + 30_000)?;
            warn!(
                order_id = order.id,
                "manual shop order notification pending; purchase retained"
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn notice_is_localized_non_pinging_and_has_a_stable_nonce() {
        let order = ShopOrder {
            id: 9,
            user_id: "123".into(),
            display_name: "Buyer".into(),
            product_name: "[item] @everyone".into(),
            price: 10,
            delivery: "manual".into(),
            role_id: None,
            status: "pending".into(),
            created_at: 0,
        };
        let value = body(&order, "credits", "pt");
        assert_eq!(value["nonce"], "shop-9");
        assert_eq!(value["enforce_nonce"], true);
        assert_eq!(value["allowed_mentions"]["parse"], json!([]));
        assert!(
            value["embeds"][0]["description"]
                .as_str()
                .unwrap()
                .contains("\\@everyone")
        );
        assert!(
            value["embeds"][0]["title"]
                .as_str()
                .unwrap()
                .starts_with("Novo pedido")
        );
        assert_ne!(
            body(&order, "credits", "ko")["embeds"][0]["title"],
            body(&order, "credits", "en")["embeds"][0]["title"]
        );
    }
    fn fixture() -> (Store, ScheduledAction) {
        let store = Store::open(":memory:").unwrap();
        store
            .set_setting("10", "community.economy.staff_channel", "20")
            .unwrap();
        store.claim_daily("10", "123", 100).unwrap();
        store
            .save_shop_product(
                "10",
                None,
                0,
                &helper_store::ShopProductInput {
                    name: "Item".into(),
                    price: 10,
                    delivery: "manual".into(),
                    role_id: None,
                },
            )
            .unwrap();
        let product = store.shop_products("10").unwrap().remove(0);
        store
            .buy_shop_product("10", "123", "Buyer", product.id, product.version, "quote")
            .unwrap();
        let job = store
            .due_scheduled_actions(i64::MAX, 100)
            .unwrap()
            .remove(0);
        (store, job)
    }
    #[tokio::test]
    async fn transient_failure_retries_the_same_nonce_without_charging_again() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            for index in 0..4 {
                let (mut socket, _) =
                    tokio::time::timeout(Duration::from_secs(5), listener.accept())
                        .await
                        .unwrap()
                        .unwrap();
                let mut request = Vec::new();
                loop {
                    let mut bytes = [0; 2048];
                    let count = socket.read(&mut bytes).await.unwrap();
                    assert!(count > 0);
                    request.extend_from_slice(&bytes[..count]);
                    if let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                        let headers = String::from_utf8_lossy(&request[..end]);
                        let length = headers
                            .lines()
                            .find_map(|line| {
                                line.to_lowercase()
                                    .strip_prefix("content-length:")
                                    .and_then(|v| v.trim().parse::<usize>().ok())
                            })
                            .unwrap_or(0);
                        if request.len() >= end + 4 + length {
                            break;
                        }
                    }
                }
                let request = String::from_utf8(request).unwrap();
                let (status, value) = if index % 2 == 0 {
                    assert!(request.starts_with("GET /channels/20 "));
                    (200, json!({"guild_id":"10","type":0}))
                } else {
                    assert!(request.starts_with("POST /channels/20/messages "));
                    let body: Value =
                        serde_json::from_str(request.split("\r\n\r\n").nth(1).unwrap()).unwrap();
                    assert_eq!(body["nonce"], "shop-1");
                    assert_eq!(body["enforce_nonce"], true);
                    (if index == 1 { 500 } else { 200 }, json!({"id":"40"}))
                };
                let body = value.to_string();
                let response = format!(
                    "HTTP/1.1 {status} Result\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                socket.write_all(response.as_bytes()).await.unwrap();
            }
        });
        let (store, job) = fixture();
        deliver(&base, "Bot synthetic", &store, &job).await.unwrap();
        assert_eq!(store.failed_shop_notices("10").unwrap(), 1);
        let retry = store
            .due_scheduled_actions(i64::MAX, 100)
            .unwrap()
            .remove(0);
        deliver(&base, "Bot synthetic", &store, &retry)
            .await
            .unwrap();
        assert!(
            store
                .due_scheduled_actions(i64::MAX, 100)
                .unwrap()
                .is_empty()
        );
        assert_eq!(store.economy_account("10", "123").unwrap().balance, 90);
        server.await.unwrap();
    }
    #[tokio::test]
    async fn expired_unknown_delivery_is_visible_and_not_reposted() {
        let (store, mut job) = fixture();
        job.4 = json!({"attempted_at":Utc::now().timestamp_millis()-121_000,"notice_channel":"20"})
            .to_string();
        store.shop_notice_state(job.0, &job.4, 0).unwrap();
        deliver("http://127.0.0.1:9", "Bot synthetic", &store, &job)
            .await
            .unwrap();
        assert_eq!(store.failed_shop_notices("10").unwrap(), 1);
        assert!(
            store
                .due_scheduled_actions(Utc::now().timestamp_millis(), 100)
                .unwrap()
                .is_empty()
        );
        assert_eq!(store.economy_account("10", "123").unwrap().balance, 90);
    }
    #[tokio::test]
    async fn unavailable_channel_is_visible_and_keeps_the_purchase() {
        let (store, job) = fixture();
        deliver("http://127.0.0.1:9", "Bot synthetic", &store, &job)
            .await
            .unwrap();
        assert_eq!(store.failed_shop_notices("10").unwrap(), 1);
        assert!(
            store
                .due_scheduled_actions(Utc::now().timestamp_millis(), 100)
                .unwrap()
                .is_empty()
        );
        assert_eq!(store.economy_account("10", "123").unwrap().balance, 90);
    }
}
